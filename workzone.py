import contextlib
import json
import logging
import re
import sys
from multiprocessing.pool import ThreadPool

import click
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from tenacity import RetryError, Retrying, stop_after_attempt, wait_fixed

REQUESTS_SESSION = None
TOKEN = None
LIMIT = "9999"
POOL_SIZE = 64
LOGGER = None
DRY_RUN = None
LOG_LEVEL = {"debug": logging.DEBUG, "info": logging.INFO, "error": logging.ERROR}
RETRIES = 5
PROJECT = None
# List of tuples: pairs of repo and branch names that are presented in BB
DATA = None
BITBUCKET_HOST = None

ENDPOINT_REVIEWERS = f"https://{BITBUCKET_HOST}/bitbucket/rest/workzoneresource/latest/branch/reviewers"
ENDPOINT_USERS = f"https://{BITBUCKET_HOST}/bitbucket/rest/api/1.0/users"
ENDPOINT_AUTOMERGE = f"https://{BITBUCKET_HOST}/bitbucket/rest/workzoneresource/latest/branch/automerge"
ENDPOINT_PROJECTS = f"https://{BITBUCKET_HOST}/bitbucket/rest/api/1.0/projects"


class MockResponse:
    def __init__(self, json_data, status_code, ok, reason):
        self.json_data = json_data
        self.status_code = status_code
        self.ok = ok
        self.reason = reason

    def json(self):
        return self.json_data


def get_default_reviewer_data(repo, branch):
    data = {
        "projectKey": PROJECT,
        "repoSlug": repo,
        "refName": f"refs/heads/{branch}",
        "refPattern": "",
        "srcRefName": "",
        "users": [],
        "groups": [],
        "mandatoryUsers": [],
        "mandatoryGroups": [],
        "topSuggestedReviewers": 0,
        "daysInPast": 0,
    }
    return data


def get_default_merge_data(repo, branch):
    data = {
        "projectKey": PROJECT,
        "repoSlug": repo,
        "refName": f"refs/heads/{branch}",
        "srcRefName": "",
        "automergeUsers": [],
        "autoMergeEnabled": False,
        "approvalQuotaEnabled": True,
        "deleteSourceBranch": False,
        "watchBuildResult": False,
        "watchTaskCompletion": False,
        "requiredBuildsCount": 0,
        "requiredSignaturesCount": 0,
        "groupQuota": 0,
        "mergeCondition": "",
        "mergeStrategyId": "noneinherit",
        "ignoreContributingReviewersApproval": False,
    }
    return data


def setup_logger(name, level=logging.INFO):
    """Configure logging module."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stderr)],
    )
    return logging.getLogger(name)


def get_session(token=None):
    global REQUESTS_SESSION
    if REQUESTS_SESSION is None:
        REQUESTS_SESSION = requests.Session()
        retry_strategy = Retry(
            total=RETRIES,
            status_forcelist=[429, 500, 501, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
            backoff_factor=1,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        REQUESTS_SESSION.mount("https://", adapter)
        REQUESTS_SESSION.mount("http://", adapter)
        REQUESTS_SESSION.verify = True
        REQUESTS_SESSION.headers["Content-Type"] = "application/json; charset=utf-8"
        if token is not None:
            REQUESTS_SESSION.headers["Authorization"] = "Bearer " + token
    return REQUESTS_SESSION


def get_all_repos():
    data = api(f"{ENDPOINT_PROJECTS}/{PROJECT}/repos?limit={LIMIT}", "GET").json()
    repos = []
    for repo in data.get("values", []):
        repos.append(repo["slug"])
    LOGGER.info(f"Found {len(repos)} repos in {PROJECT} project")
    return repos


def get_branches(repo, branch_regex):
    LOGGER.debug(f"[{PROJECT}][{repo}] Checking for branches...")
    print(f"{ENDPOINT_PROJECTS}/{PROJECT}/repos/{repo}/branches?limit={LIMIT}")
    branch_data = (
        api(
            f"{ENDPOINT_PROJECTS}/{PROJECT}/repos/{repo}/branches?limit={LIMIT}",
            "GET",
        )
        .json()
        .get("values", [])
    )
    branches = []
    for branch in branch_data:
        if re.search(branch_regex, branch["displayId"]):
            LOGGER.debug(f'[{PROJECT}][{repo}] Found {branch["displayId"]}')
            branches.append(branch["displayId"])
    return (repo, branches)


def api(url, method, data=None):
    session = get_session(TOKEN)
    # In case of failure mock is returned, since it is empty
    # no actions will be performed after
    response = MockResponse(
        {}, 999, False, "It is a mock response; something went wrong"
    )
    try:
        if method == "GET":
            response = session.get(url)
        elif method == "POST":
            if DRY_RUN:
                LOGGER.debug(f"Skipping {method} due to dry-run")
                return MockResponse(
                    {}, 999, False, "It is a mock response due to dry-run"
                )
            response = session.post(url, json.dumps(data))
        elif method == "DELETE":
            if DRY_RUN:
                LOGGER.debug(f"Skipping {method} due to dry-run")
                return MockResponse(
                    {}, 999, False, "It is a mock response due to dry-run"
                )
            response = session.delete(url, data=json.dumps(data))
        else:
            LOGGER.error(f"No such method {method}")
            return
    except Exception as e:
        LOGGER.error(f"Failed to {method} URL: {url}. Exception: {e}.")
        return response
    if response.status_code != 200:
        LOGGER.warning(
            f"Response={response.status_code} for {method} {url}; data={data}"
        )
    return response


def get_criteria(repo, branch):
    data = api(f"{ENDPOINT_AUTOMERGE}/{PROJECT}/{repo}", "GET").json()
    for record in data:
        if record.get("refName") and (record["refName"].split("/")[-1] == branch.split("/")[-1]):
            LOGGER.debug(
                f'[{PROJECT}][{branch}][{repo}] Found merge criteria: {record["mergeCondition"]}'
            )
            return record
    # This is the case when branch doesn't have any merge data set
    LOGGER.debug(f"[{PROJECT}][{branch}][{repo}] No automerge configuration set")


def get_reviewers(repo, branch):
    data = api(f"{ENDPOINT_REVIEWERS}/{PROJECT}/{repo}", "GET").json()
    for record in data:
        if record["refName"].split("/")[-1] == branch.split("/")[-1]:
            LOGGER.debug(
                f'[{PROJECT}][{branch}][{repo}] Found reviewers configuration: users={[user["name"] for user in record["users"]]}, groups={record["groups"]}'
            )
            return record
    # This is the case when a branch doesn't have any reviewers specified
    LOGGER.debug(f"[{PROJECT}][{branch}][{repo}] No reviewers configuration set")


def get_user(user_id):
    data = api(f"{ENDPOINT_USERS}/{user_id}", "GET").json()
    if not data or "errors" in data:
        LOGGER.error(f"No such user: {user_id}")
        return
    else:
        LOGGER.debug(f"Fetched {user_id} info")
        return data


def _set_merge_criteria(repo, branch, criteria):
    if not all([PROJECT, repo, branch, criteria]):
        LOGGER.error(
            f"One (or more) of the required arguments is not specified: PROJECT: {PROJECT}, repo: {repo}, branch: {branch}, criteria: {criteria}"
        )
        return
    current_automerge = get_criteria(repo, branch)
    if current_automerge:
        # If it is the same as the new one - don't update it
        if current_automerge["mergeCondition"] == criteria:
            LOGGER.info(
                f"[{PROJECT}][{branch}][{repo}] Already has criteria set to {criteria}"
            )
            return
        new_automerge = current_automerge
    else:
        new_automerge = get_default_merge_data(repo, branch)
    new_automerge["mergeCondition"] = criteria
    LOGGER.info(
        f'[{PROJECT}][{branch}][{repo}] Going to replace mergeCondition with "{criteria}"'
    )
    response = api(f"{ENDPOINT_AUTOMERGE}/{PROJECT}/{repo}", "POST", new_automerge)
    # For some reason post always returns 500, so we will check if data got applied
    if not response.ok:
        if response.status_code == 500:
            current_automerge = get_criteria(repo, branch)
            if current_automerge["mergeCondition"] != criteria:
                LOGGER.error(
                    f"[{PROJECT}][{branch}][{repo}] Failed to update merge criteria"
                )
            else:
                LOGGER.info(
                    f'[{PROJECT}][{branch}][{repo}] Set mergeCondition to "{criteria}"'
                )
        else:
            LOGGER.error(
                f"[{PROJECT}][{branch}][{repo}] Failed to set merge criteria: {response.reason}"
            )
    else:
        # This line won't be executed if merge crtirea got set with 500 resp, but let's keep just in case
        LOGGER.info(f'[{PROJECT}][{branch}][{repo}] Set mergeCondition to "{criteria}"')


def _remove_merge_criteria(repo, branch):
    if not all([PROJECT, repo, branch]):
        LOGGER.error(
            f"One (or more) of the required arguments is not specified: PROJECT: {PROJECT}, repo: {repo}, branch: {branch}"
        )
        return
    current_automerge = get_criteria(repo, branch)
    if current_automerge:
        LOGGER.info(
            f"[{PROJECT}][{branch}][{repo}] Going to remove full automerge configuration"
        )
        resp = api(
            f"{ENDPOINT_AUTOMERGE}/{PROJECT}/{repo}", "DELETE", current_automerge
        )
        if resp.ok:
            LOGGER.info(
                f"[{PROJECT}][{branch}][{repo}] Successfully deleted automerge configuration"
            )
        else:
            LOGGER.error(
                f"[{PROJECT}][{branch}][{repo}] Failed to delete automerge configuration: {resp.reason}"
            )
    else:
        LOGGER.info(f"[{PROJECT}][{branch}][{repo}] Nothing to delete")


def _add_reviewer(repo, branch, user_data):
    if not all([PROJECT, repo, branch, user_data]):
        LOGGER.error(
            f"One (or more) of the required arguments is not specified: PROJECT: {PROJECT}, repo: {repo}, branch: {branch}, user_id: {user_data}"
        )
        return
    current_reviewers = get_reviewers(repo, branch)
    if current_reviewers:
        if user_data not in current_reviewers["users"]:
            new_reviewers = current_reviewers
        else:
            LOGGER.info(
                f'[{PROJECT}][{branch}][{repo}] User {user_data["name"]} is already added'
            )
            return
    else:
        new_reviewers = get_default_reviewer_data(repo, branch)
    new_reviewers["users"].append(user_data)
    LOGGER.debug(
        f'[{PROJECT}][{branch}][{repo}] Going to add {user_data["name"]} to reviewers'
    )
    response = api(f"{ENDPOINT_REVIEWERS}/{PROJECT}/{repo}", "POST", new_reviewers)
    if not response.ok:
        LOGGER.error(
            f'[{PROJECT}][{branch}][{repo}] Failed to add {user_data["name"]} to reviewers: {response.reason}'
        )
    else:
        LOGGER.info(
            f'[{PROJECT}][{branch}][{repo}] Successfully added {user_data["name"]} to reviewers'
        )


def _add_reviewer_group(repo, branch, group):
    if not all([PROJECT, repo, branch, group]):
        LOGGER.error(
            f"One (or more) of the required arguments is not specified: PROJECT: {PROJECT}, repo: {repo}, branch: {branch}, group: {group}"
        )
        return
    current_reviewers = get_reviewers(repo, branch)
    if current_reviewers:
        if group not in current_reviewers["groups"]:
            new_reviewers = current_reviewers
        else:
            LOGGER.info(f"[{PROJECT}][{branch}][{repo}] Group {group} is already added")
            return
    else:
        new_reviewers = get_default_reviewer_data(repo, branch)
    new_reviewers["groups"].append(group)
    LOGGER.debug(f"[{PROJECT}][{branch}][{repo}] Going to add {group} to reviewers")
    response = api(f"{ENDPOINT_REVIEWERS}/{PROJECT}/{repo}", "POST", new_reviewers)
    if not response.ok:
        LOGGER.error(
            f"[{PROJECT}][{branch}][{repo}] Failed to add {group} to reviewers: {response.reason}"
        )
    else:
        LOGGER.info(
            f'[{PROJECT}][{branch}][{repo}] Successfully added {group} to reviewers: {new_reviewers["groups"]}'
        )


def _remove_reviewers(repo, branch):
    if not all([PROJECT, repo, branch]):
        LOGGER.error(
            f"One (or more) of the required arguments is not specified: project={PROJECT}, repo={repo}, branch={branch}"
        )
        return
    current_reviewers = get_reviewers(repo, branch)
    if current_reviewers:
        LOGGER.info(
            f"[{PROJECT}][{branch}][{repo}] Going to remove full reviewers configuration"
        )
        resp = api(
            f"{ENDPOINT_REVIEWERS}/{PROJECT}/{repo}", "DELETE", current_reviewers
        )
        if resp.ok:
            LOGGER.info(
                f"[{PROJECT}][{branch}][{repo}] Successfully deleted reviewers configuration"
            )
        else:
            LOGGER.error(
                f"[{PROJECT}][{branch}][{repo}] Failed to delete reviewers configuration: {resp.reason}"
            )
    else:
        LOGGER.info(f"[{PROJECT}][{branch}][{repo}] Nothing to delete")


def _set_reviewers(repo, branch, users, groups):
    if not all([PROJECT, repo, branch]):
        LOGGER.error(
            f"One (or more) of the required arguments is not specified: project={PROJECT}, repo={repo}, branch={branch}"
        )
        return
    new_user_names = [user["name"] for user in users]
    needs_update = False
    # Preserve other reviewers configs except for 'users' and 'groups'
    current_reviewers = get_reviewers(repo, branch)
    if current_reviewers:
        new_reviewers = current_reviewers
        # Get diff on users
        curr_users = [user["name"] for user in current_reviewers["users"]]
        users_to_delete = set(curr_users) - set(new_user_names)
        users_to_add = set(new_user_names) - set(curr_users)
        if users_to_delete or users_to_add:
            needs_update = True
            LOGGER.info(
                f"[{PROJECT}][{branch}][{repo}] Users to be added: {users_to_add}; deleted: {users_to_delete}"
            )
        # Get diff on groups
        curr_groups = current_reviewers["groups"]
        groups_to_delete = set(curr_groups) - set(groups)
        groups_to_add = set(groups) - set(curr_groups)
        if groups_to_delete or groups_to_add:
            needs_update = True
            LOGGER.info(
                f"[{PROJECT}][{branch}][{repo}] Groups to be added: {groups_to_add}; deleted: {groups_to_delete}"
            )
    else:
        LOGGER.info(
            f"[{PROJECT}][{branch}][{repo}] No reviewers configuration exists, going to add users={new_user_names}, groups={groups}"
        )
        needs_update = True
        new_reviewers = get_default_reviewer_data(repo, branch)
    new_reviewers["users"] = users
    new_reviewers["groups"] = groups
    if needs_update:
        response = api(f"{ENDPOINT_REVIEWERS}/{PROJECT}/{repo}", "POST", new_reviewers)
        if not response.ok:
            LOGGER.error(
                f"[{PROJECT}][{branch}][{repo}] Failed to update reviewers: reason={response.reason}"
            )
        else:
            LOGGER.info(
                f"[{PROJECT}][{branch}][{repo}] Successfully set reviewers: users={new_user_names}, groups={groups}"
            )
    else:
        LOGGER.info(
            f"[{PROJECT}][{branch}][{repo}] Skip update, reviewers configuration already matches desired state"
        )


def run_in_parallel(func, *args):
    # POOL_SIZE=1 is a special case that can be used for debbuging
    cm = ThreadPool(POOL_SIZE) if POOL_SIZE > 1 else contextlib.nullcontext()
    with cm as pool:
        parallel_map = pool.starmap if POOL_SIZE > 1 else map
        parallel_map(func, [pair + args for pair in DATA])


def validate_users_in_parallel(user_ids):
    users = []
    LOGGER.debug(f"Getting info for {user_ids} users")
    if user_ids:
        cm = ThreadPool(POOL_SIZE) if POOL_SIZE > 1 else contextlib.nullcontext()
        with cm as pool:
            parallel_map = pool.map if POOL_SIZE > 1 else map
            users = parallel_map(get_user, user_ids)
    return users


def validate_branch_regexp(ctx, param, value):
    try:
        re.compile(value)
    except re.error:
        raise click.BadParameter(f"invalid regular expression '{value}'")
    return value


@click.group()
@click.option("--dry-run/--no-dry-run", default=False)
@click.option(
    "--log-level",
    default="info",
    help="Options: debug, info or error.",
    show_default=True,
)
@click.option(
    "--bb-host",
    required=True,
    help="A network host where your BB is located",
    envvar="BB_HOST",
)
@click.option(
    "--bb-token",
    required=True,
    help="Bitbucket token; can be passed by defining the BB_TOKEN env var.",
    envvar="BB_TOKEN",
)
@click.option(
    "--branch-regex",
    required=True,
    help="Regex to match a branch name",
    callback=validate_branch_regexp,
)
@click.option(
    "--repo",
    help="Bitbucket repository within the specified project, if omitted applies to all",
)
@click.option(
    "--project",
    help="Bitbucket project",
    required=True,
    envvar="BB_PROJECT"
)
@click.pass_context
def cli(ctx, project, repo, branch_regex, bb_token, bb_host, log_level, dry_run):
    ctx.ensure_object(dict)
    global LOGGER
    LOGGER = setup_logger("workzone", LOG_LEVEL[log_level])
    global TOKEN
    TOKEN = bb_token
    global DRY_RUN
    DRY_RUN = dry_run
    global PROJECT
    PROJECT = project
    global BITBUCKET_HOST
    BITBUCKET_HOST = bb_host
    global ENDPOINT_REVIEWERS
    ENDPOINT_REVIEWERS = f"https://{BITBUCKET_HOST}/bitbucket/rest/workzoneresource/latest/branch/reviewers"
    global ENDPOINT_USERS
    ENDPOINT_USERS = f"https://{BITBUCKET_HOST}/bitbucket/rest/api/1.0/users"
    global ENDPOINT_AUTOMERGE
    ENDPOINT_AUTOMERGE = f"https://{BITBUCKET_HOST}/bitbucket/rest/workzoneresource/latest/branch/automerge"
    global ENDPOINT_PROJECTS
    ENDPOINT_PROJECTS = f"https://{BITBUCKET_HOST}/bitbucket/rest/api/1.0/projects"
    # Hide urllib3.connectionpool WARNING - Connection pool is full, discarding connection
    logging.getLogger("urllib3").setLevel(logging.ERROR)
    LOGGER.debug("Starting workzone cli.")
    global DATA
    DATA = []
    if not repo:
        repos = get_all_repos()
        cm = ThreadPool(POOL_SIZE) if POOL_SIZE > 1 else contextlib.nullcontext()
        with cm as pool:
            parallel_map = pool.starmap if POOL_SIZE > 1 else map
            res = parallel_map(get_branches, [(repo, branch_regex) for repo in repos])
            for entry in res:
                if entry[1]:
                    DATA.extend(list(map(lambda x: (entry[0], x), entry[1])))
    else:
        res = get_branches(repo, branch_regex)
        if res[1]:
            DATA.extend(list(map(lambda x: (res[0], x), res[1])))
    LOGGER.info(f"Found {len(DATA)} branches that matches {branch_regex} regex")


@cli.command()
@click.argument("criteria")
@click.pass_context
def set_merge_criteria(ctx, criteria):
    run_in_parallel(_set_merge_criteria, criteria)


@cli.command()
@click.pass_context
def remove_merge_criteria(ctx):
    run_in_parallel(_remove_merge_criteria)


@cli.command()
@click.pass_context
@click.argument("user_id")
def add_reviewer(ctx, user_id):
    user_data = get_user(user_id)
    if not user_data:
        return
    run_in_parallel(_add_reviewer, user_data)


@cli.command()
@click.pass_context
@click.argument("group")
def add_reviewer_group(ctx, group):
    run_in_parallel(_add_reviewer_group, group)


@cli.command()
@click.pass_context
def remove_reviewers(ctx):
    run_in_parallel(_remove_reviewers)


@cli.command()
@click.option(
    "--group",
    default=[],
    help="A group to be added to reviewers; can pass multiple: --group 1 --group 2",
    multiple=True,
    show_default=True,
)
@click.option(
    "--user",
    default=[],
    help="A user to be added to reviewers; can pass multiple: --user 1 --user 2",
    multiple=True,
    show_default=True,
)
@click.pass_context
def set_reviewers(ctx, user, group):
    # Get user data first
    validated_users = validate_users_in_parallel(user)
    user_list = list(filter(None, validated_users))
    if not (user_list or group):
        LOGGER.error(
            f"Expect user id(s) or reviewer group(s) to be specified, got: ids={user}, groups={group}"
        )
        return
    run_in_parallel(_set_reviewers, user_list, group)


if __name__ == "__main__":
    cli(obj={})
