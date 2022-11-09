---
layout: default
title: Vihreiden ohjelmat
---

# Vihreiden ohjelmat

{% for page in site.pages %}
 - [{{ page.year }}: {{ page.title }} ({{ page.type }})]({{ site.url }}/{{ page.url }})
{% endfor %}
