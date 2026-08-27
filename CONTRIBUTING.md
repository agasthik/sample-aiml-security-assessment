# Contributing Guidelines

Thank you for your interest in contributing to our project. Whether it's a bug report, new feature, correction, or additional
documentation, we greatly value feedback and contributions from our community.

Please read through this document before submitting any issues or pull requests so that we have all the necessary
information to effectively respond to your bug report or contribution.


## Reporting Bugs/Feature Requests

We welcome you to use the GitHub issue tracker to report bugs or suggest features.

When filing an issue, please check existing open, or recently closed, issues to make sure somebody else hasn't already
reported the issue. Please try to include as much information as you can. Details like these are incredibly useful:

* A reproducible test case or series of steps
* The version of our code being used
* Any modifications you've made relevant to the bug
* Anything unusual about your environment or deployment


## Contributing through Pull Requests
Contributions through pull requests are much appreciated. Before sending us a pull request, make sure that:

1. You are working against the latest source on the *main* branch.
2. You check existing open, and recently merged, pull requests to make sure someone else hasn't addressed the problem already.
3. You open an issue to discuss any significant work - we would hate for your time to be wasted.

To send us a pull request, please:

1. Fork the repository.
2. Modify the source; please focus on the specific change you are contributing. If you also reformat all the code, it will be hard for us to focus on your change.
3. Make sure local tests pass.
4. Run linting, formatting, and tests locally before pushing:

   ```bash
   # Create a Python 3.12 virtual environment once, then use it for all tooling.
   python3.12 -m venv .venv
   PYTHON="$PWD/.venv/bin/python"
   RUFF="$PWD/.venv/bin/ruff"

   $PYTHON -m pip install --upgrade pip
   $PYTHON -m pip install ruff \
     -r tests/requirements.txt \
     -r aiml-security-assessment/functions/security/agentcore_assessments/requirements.txt \
     -r aiml-security-assessment/functions/security/bedrock_assessments/requirements.txt \
     -r aiml-security-assessment/functions/security/cleanup_bucket/requirements.txt \
     -r aiml-security-assessment/functions/security/generate_consolidated_report/requirements.txt \
     -r aiml-security-assessment/functions/security/iam_permission_caching/requirements.txt \
     -r aiml-security-assessment/functions/security/owasp_assessments/requirements.txt \
     -r aiml-security-assessment/functions/security/resolve_regions/requirements.txt \
     -r aiml-security-assessment/functions/security/responsible_ai_grc_assessments/requirements.txt \
     -r aiml-security-assessment/functions/security/sagemaker_assessments/requirements.txt
   $PYTHON -m pip check

   # Required by the test fixtures. These are test values, not AWS credentials.
   export AIML_ASSESSMENT_BUCKET_NAME=test-assessment-bucket
   export AWS_DEFAULT_REGION=us-east-1
   export AWS_ACCESS_KEY_ID=testing
   export AWS_SECRET_ACCESS_KEY=testing

   # Match CI by linting the Python files changed by the pull request.
   CHANGED_PY=$(git diff --name-only --diff-filter=ACMR origin/main...HEAD -- '*.py')
   $RUFF check $CHANGED_PY
   $RUFF format --check $CHANGED_PY

   # Keep these as separate pytest sessions. Several Lambda packages import a
   # top-level app.py, so combining suites can cause module-name collisions.
   $PYTHON -m pytest tests/ -v --tb=short
   $PYTHON -m pytest aiml-security-assessment/functions/security/responsible_ai_grc_tests/ -v --tb=short
   $PYTHON -m pytest tests/test_consolidate_responsible_ai_grc.py -v --tb=short

   (cd aiml-security-assessment/functions/security/generate_consolidated_report \
     && $PYTHON -m pytest test_generate_report.py -v --tb=short)
   ```

   If your change modifies a SAM or deployment template, also run the
   CloudFormation lint and SAM validation/build commands documented in the
   [Developer Guide](docs/DEVELOPER_GUIDE.md).

5. Commit to your fork using clear commit messages.
6. Send us a pull request, answering any default questions in the pull request interface.
7. Pay attention to any automated CI failures reported in the pull request, and stay involved in the conversation.

### Automated CI Checks

The following checks run automatically on every pull request:

- **Python Code Quality** — `ruff check` (lint) and `ruff format --check` (formatting) on changed Python files
- **AI/ML Security Assessment Tests** — core, Responsible AI GRC, consolidator, and report-pipeline pytest sessions on Python 3.12
- **CloudFormation Lint** — `cfn-lint` validation of deployment and SAM templates
- **SAM Validate & Build** — `sam validate --lint` and `sam build` on SAM templates
- **ASH Security Scan** — [Automated Security Helper](https://github.com/awslabs/automated-security-helper) scans changed files for secrets, dependency vulnerabilities, and IaC misconfigurations

All checks must pass before a pull request can be merged.

GitHub provides additional document on [forking a repository](https://help.github.com/articles/fork-a-repo/) and
[creating a pull request](https://help.github.com/articles/creating-a-pull-request/).


## Finding contributions to work on
Looking at the existing issues is a great way to find something to contribute on. As our projects, by default, use the default GitHub issue labels (enhancement/bug/duplicate/help wanted/invalid/question/wontfix), looking at any 'help wanted' issues is a great place to start.


## Code of Conduct
This project has adopted the [Amazon Open Source Code of Conduct](https://aws.github.io/code-of-conduct).
For more information see the [Code of Conduct FAQ](https://aws.github.io/code-of-conduct-faq) or contact
opensource-codeofconduct@amazon.com with any additional questions or comments.


## Security issue notifications
If you discover a potential security issue in this project we ask that you notify AWS/Amazon Security through our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/). Please do **not** create a public github issue.


## Licensing

See the [LICENSE](LICENSE) file for our project's licensing. We ask you to confirm the licensing of your contribution.
