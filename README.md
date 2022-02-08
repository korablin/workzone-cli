# workzone-cli
A cli tool written in python for managing merge criteria and reviewers on Bitbucket for multiple repos in parallel via the Workzone plugin

## Setup virtual environment

In the cloned workzone-cli directory run next command to create and activate new venv
```bash
make prod-venv; source .venv/bin/activate
```

If needed you can run `make clean` to delete downloaded pakcages and purge `.venv` directory

## Usage
You need to have Bitbucket token with admin rights passed as `--bb-token` option, also `--bb-project` and `--bb-host`
All can be set via env vars
```
export BB_TOKEN=suPerSecretT0kEn
export BB_PROJECT=PROJ-1
export BB_HOST=bitbucket-host-1.mycompany.com
```
Now you can finally `set-reviewers` like this
```bash
python workzone.py --dry-run --project PROJ-1 --branch-regex '^master$' --repo my-repo set-reviewers --group topReviewersGroup --user me --user myself --user I                
workzone INFO - Found 1 branches that matches ^master$ regex
workzone WARNING - Response=404 for GET https://bitbucket-host-1.mycompany.com /bitbucket/rest/api/1.0/users/I; data=None
workzone ERROR - No such user: I
workzone INFO - [PROJ-1][master][my-repo] Users to be added: {'me', 'myself'}; deleted: {'someOneElse'}
workzone INFO - [PROJ-1][master][my-repo] Groups to be added: {'topReviewersGroup'}; deleted: set()
workzone ERROR - [PROJ-1][master][my-repo] Failed to update reviewers: reason=It is a mock response due to dry-run
```
The command above was executed in a `dry-run mode` meaning that no changes will be made actually.
You can see in the logs what the tool is going to do.

In this case it will add 2 new reviewers: "me", "myself" and delete "someOneElse".
Note: if you want to add a new reviewer without deleting anyone else, you should run `add-reviewer`.

It also says that it did not find user "I", note that it does not cause the tool failure.

## Quirks and features
If you omit `--repo` option and pass `--branch-regex '.'` it will configure all the existing branches in all the repositories within your Bitbucket project in parallel.
For example, it takes just `15 seconds` to configure `10,000+ branches` with a regular internet connection from a coffee shop.

## Available commands
Use the command below
```bash
python workzone.py --help
Usage: workzone.py [OPTIONS] COMMAND [ARGS]...

Options:
    --dry-run / --no-dry-run
    --log-level TEXT          Options: debug, info or error.  [default: info]
    --bb-host TEXT            A network host where your BB is located
                              [required]
    --bb-token TEXT           Bitbucket token; can be passed by defining the
                              BB_TOKEN env var.  [required]
    --branch-regex TEXT       Regex to match a branch name  [required]
    --repo TEXT               Bitbucket repository within the specified project,
                              if omitted applies to all
    --project TEXT            Bitbucket project  [required]
    --help                    Show this message and exit.

Commands:
  add-reviewer              # Adds a reviewer(s) that exist in Bitbucket already
  add-reviewer-group        # Adds a reviewer-group
  remove-merge-criteria     # Deletes merge critria completely
  remove-reviewers          # Deletes all the reviewers: groups and individual ones
  set-merge-criteria        # Replaces or sets a new merge criteria
  set-reviewers             # Sets reviewers and/or reviewer-group, removes those that were passed
                            # but were already configured
```

### Virtual environment for developers
To add a new dependency (or update existing) you need to update `pyproject.toml` with a new python package
and then install it using [poetry](https://github.com/python-poetry/poetry) tool
```bash
make install
```
Once the package is installed via poetry, you can update `requirements.txt` running the next command
```bash
make generate-requirements
```
This way we can keep poetry decoupled from the cli tool for the end user
