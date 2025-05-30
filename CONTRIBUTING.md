# Contributing to Infra Clarity

First off, thanks for taking the time to contribute! ❤️

All types of contributions are encouraged and valued. Please make sure to read the relevant section before making your contribution. It will make it a lot easier for us maintainers and smooth out the experience for all involved.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [I Have a Question](#i-have-a-question)
- [I Want To Contribute](#i-want-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Your First Code Contribution](#your-first-code-contribution)
  - [Improving The Documentation](#improving-the-documentation)
- [Styleguides](#styleguides)
  - [Commit Messages](#commit-messages)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to [your-email@example.com](mailto:your-email@example.com).

## I Have a Question

> If you want to ask a question, we assume that you have read the available [Documentation](https://github.com/yourusername/infra-clarity#readme).

Before you ask a question, it is best to search for existing [Issues](https://github.com/yourusername/infra-clarity/issues) that might help you. In case you have found a suitable issue and still need clarification, you can write your question in this issue. It is also advisable to search the internet for answers first.

If you then still feel the need to ask a question and need clarification, we recommend the following:

- Open an [Issue](https://github.com/yourusername/infra-clarity/issues/new).
- Provide as much context as you can about what you're running into.
- Provide project and platform versions (python, operating system, etc.), depending on what seems relevant.

We will then take care of the issue as soon as possible.

## I Want To Contribute

> ### Legal Notice
> When contributing to this project, you must agree that you have authored 100% of the content, that you have the necessary rights to the content and that the content you contribute may be provided under the project license.

### Reporting Bugs

#### Before Submitting a Bug Report

A good bug report shouldn't leave others needing to chase you up for more information. Therefore, we ask you to investigate carefully, collect information and describe the issue in detail in your report.

#### How Do I Submit a Good Bug Report?

We use GitHub issues to track bugs and errors. If you run into an issue with the project:

- Open an [Issue](https://github.com/yourusername/infra-clarity/issues/new). (Since we can't be sure at this point whether it is a bug or not, we ask to not talk about a bug yet and not to label the issue.)
- Explain the behavior you would expect and the actual behavior.
- Please include the output of `infra-clarity --version`.
- If possible, add a minimal example that reproduces the issue.

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion for Infra Clarity, including completely new features and minor improvements to existing functionality.

#### How Do I Submit a Good Enhancement Suggestion?

Enhancement suggestions are tracked as [GitHub issues](https://github.com/yourusername/infra-clarity/issues).

- Use a **clear and descriptive title** for the issue to identify the suggestion.
- Provide a **step-by-step description** of the suggested enhancement in as many details as possible.
- **Describe the current behavior** and **explain which behavior you expected to see** instead and why.
- **Explain why this enhancement would be useful** to most Infra Clarity users.
- List some other applications where this enhancement exists, if any.
- Specify which version of Infra Clarity you're using.
- Specify the name and version of the OS you're using.

### Your First Code Contribution

1. Fork the repository on GitHub.
2. Clone the fork to your local machine.
3. Create a new branch for your changes.
4. Make your changes following the [styleguides](#styleguides).
5. Commit your changes with a descriptive commit message.
6. Push your changes to your fork.
7. Open a pull request against the main repository.

### Improving The Documentation

Documentation is a crucial part of any open-source project. If you see a typo, think something could be clearer, or want to add an example, please open a pull request with your suggested changes.

## Styleguides

### Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line
- When only changing documentation, include `[ci skip]` in the commit title

### Python Code Style

We use:
- Black for code formatting
- isort for import sorting
- flake8 for linting
- mypy for type checking

Run the following before committing:

```bash
black .
isort .
flake8
mypy infra_clarity
```

## Attribution

This CONTRIBUTING.md is adapted from the [Contributing Generator](https://github.com/bttger/contributing-gen), available under the [MIT License](https://github.com/bttger/contributing-gen/blob/main/LICENSE).
