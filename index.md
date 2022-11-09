---
layout: default
title: Vihreiden ohjelmat
---

# Vihreiden ohjelmat

{% assign groups = site.pages |group_by:"year" %}
{% assign sgroups = groups |sort:"name" |reverse %}
{% for group in sgroups %}
## {{ group.name|default:"other" }}
{% for item in group.items %}
 - [{{ item.title }} ({{ item.type }})]({{ site.url }}{{ item.url }})

{% endfor %}
{% endfor %}
