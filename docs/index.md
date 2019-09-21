---
layout: default
title: Home
nav_order: 1
description: "Restify middleware that validates a JsonWebToken."
permalink: /
---

# Getting started
### Installation

| Package Manager        | Command                                |
|:-----------------------|:---------------------------------------|
| NPM                    | `npm install -S restify-jwt-community` |
| YARN                   | `yarn add restify-jwt-community`       |

### Configure
- [See configuration options]({{ site.baseurl }}{% link usage.md %})

## Project Status
<p align="center">
    <a href="https://www.npmjs.com/package/restify-jwt-community" alt="NPM" target="_blank">
        <img src="https://img.shields.io/npm/v/restify-jwt-community.svg?style=for-the-badge" /></a>
    <a href="https://github.com/frbuceta/restify-jwt-community" alt="GitHub last commit" target="_blank">
        <img src="https://img.shields.io/github/last-commit/frbuceta/restify-jwt-community.svg?color=blue&style=for-the-badge" /></a>
    <a href="https://github.com/frbuceta/restify-jwt-community/issues" alt="GitHub issues" target="_blank">
        <img src="https://img.shields.io/github/issues/frbuceta/restify-jwt-community.svg?color=blue&style=for-the-badge" /></a>
    <a href="https://github.com/frbuceta/restify-jwt-community/pulls" alt="GitHub pull requests" target="_blank">
        <img src="https://img.shields.io/github/issues-pr/frbuceta/restify-jwt-community.svg?color=blue&style=for-the-badge" /></a>
</p>

---

<p align="center">
    <a href="#"><img src="https://img.shields.io/david/frbuceta/restify-jwt-community.svg?style=flat-square" /></a>
    <a href="#"><img src="https://img.shields.io/david/dev/frbuceta/restify-jwt-community.svg?style=flat-square" /></a>
    <a href="#"><img src="https://img.shields.io/david/peer/frbuceta/restify-jwt-community.svg?style=flat-square" /></a>
</p>

<p align="center">
    <a href="#" alt="Travis branch"><img src="https://img.shields.io/travis/com/frbuceta/restify-jwt-community/master.svg?style=flat-square" /></a>
    <a href="#" alt="Coveralls github branch"><img src="https://img.shields.io/coveralls/github/frbuceta/restify-jwt-community/master.svg?style=flat-square" /></a>
</p>

## About the project

Restify JWT Community is &copy; 2017-2019 by [{{ site.github.owner.name }}]({{ site.github.owner.html_url }}){:target="_blank"}.

### Credits

Based on [auth0/express-jwt](https://github.com/auth0/express-jwt) and [amrav/restify-jwt](https://github.com/amrav/restify-jwt).

### License

Restify JWT Community is distributed by an [MIT license]({{ site.github.repository_url }}/tree/master/LICENSE){:target="_blank"}.

### Contributing

    Anyone can propose ideas. Anyone can help.

#### Thank you to the contributors of Restify JWT Community!

<ul class="list-style-none">
{% for contributor in site.github.contributors %}
  <li class="d-inline-block mr-1">
     <a href="{{ contributor.html_url }}"><img src="{{ contributor.avatar_url }}" width="32" height="32" alt="{{ contributor.login }}"/></a>
  </li>
{% endfor %}
</ul>
