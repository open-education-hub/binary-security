# Binary Security

[![copying.md](https://img.shields.io/static/v1?label=license&message=CCBY-SA4.0&color=%23385177)](https://github.com/open-education-hub/binary-security/blob/master/COPYING.md)
[![copying.md](https://img.shields.io/static/v1?label=license&message=BSD-3-clause&color=%23385177)](https://github.com/open-education-hub/binary-security/blob/master/COPYING.md)
[![discord](https://img.shields.io/badge/users-93-7589D0?logo=discord)](www.bit.ly/OpenEduHub)
[![contributors](https://img.shields.io/github/contributors/open-education-hub/binary-security)](https://github.com/open-education-hub/binary-security/graphs/contributors)
[![reddit](https://img.shields.io/reddit/subreddit-subscribers/OpenEducationHub?style=social)](https://www.reddit.com/r/OpenEducationHub/)
[![twitter](https://img.shields.io/twitter/url?style=social&url=https%3A%2F%2Ftwitter.com%2FOpenEduHub)](https://twitter.com/OpenEduHub)
[![youtube](https://img.shields.io/youtube/channel/views/UCumS6d-kaVXreY46eZLtEvA?style=social)](https://www.youtube.com/@OpenEduHub/)

These are open educational resources ([OER](https://en.wikipedia.org/wiki/Open_educational_resources)) for Binary Security classes.

## Using the Content

Content is located in the `chapters/` directory.
Each chapter has its own directory:

- [Binary Analysis](chapters/binar-analysis)
- [Exploitation Techniques](chapters/exploitation-techniques)
- [Mitigations and Defensive Strategies](chapters/mitigations-and-defensive-strategies)
- [Extra](chapters/extra)

### Chapter Contents

Chapters consists of sections, each presenting a given topic.
Each chapter has a directory, with a subdirectory for each section.
Content types are stored for each section.

Content is written in [GitHub Markdown](https://guides.github.com/features/mastering-markdown/).

### Contributing

Contributions are welcome.
See the [contribution guide](CONTRIBUTING.md) on how you could report or fix issues and on how you can improve the content.

Reviewers are requested to follow the [reviewing guide](REVIEWING.md).

## Publishing the Content

In order to publish the content of this repository, we use a GitHub workflow located in `.github/workflows/deployment.yml`.
This workflow will build the site using [Docusaurus](https://docusaurus.io/) and publish the contents to <https://open-education-hub.github.io/methodology/>.

### Running Locally

When testing locally, you will have to build the container that will run the builder based on the [`Dockerfile`](Dockerfile).
For this, the simplest way is the use the [`Makefile`](Makefile).

To generate the web contents locally, run:

```console
make
```

To view the local contents, start a web server by running the command:

```console
make serve
```

As the output of the command tells, point your browser to `http://localhost:8080/binary-security`.
