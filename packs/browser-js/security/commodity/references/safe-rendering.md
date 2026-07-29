# Rendering untrusted data in a browser without building markup from it

The template literal is not the problem. Building markup by concatenating a string you did
not author is. Below are the three shapes that work, in the order to reach for them, and the
four ways teams get this wrong that look correct in review.

## 1. Set text, not markup (reach for this first)

If the value is displayed as text — a name, a description, a note, an error message — assign
it to `textContent` and never to `innerHTML`. There is nothing to escape because nothing is
parsed as HTML.

```js
// before: the value is parsed as markup
card.innerHTML = `<div class="title">${v.make} ${v.model}</div>`;

// after: the element is markup, the value is text
const title = document.createElement('div');
title.className = 'title';
title.textContent = `${v.make} ${v.model}`;   // a template literal is fine HERE
card.appendChild(title);
```

Note what did *not* change: the template literal is still used, for the text. Interpolation
is safe; interpolation **into markup** is not.

## 2. Static skeleton, then fill it

For a card or row with fixed structure, write the structure once as markup with empty slots,
then fill the slots with text. This keeps the readable template and removes every injection
point.

```js
function card(v) {
  const el = document.createElement('div');
  el.className = 'card';
  el.innerHTML = `
    <img alt="pic">
    <div class="title"></div>
    <div class="desc"></div>`;              // no interpolation: constant markup
  el.querySelector('.title').textContent = `${v.make} ${v.model}`;
  el.querySelector('.desc').textContent = v.description;
  el.querySelector('img').src = safeUrl(v.image);   // see §3
  return el;
}
grid.replaceChildren(...items.map(card));
```

## 3. Attributes, which need their own answer

`textContent` does not help inside an attribute. Use `setAttribute`, and for anything that
takes a URL, validate the scheme — an `href` or `src` of `javascript:...` executes.

```js
function safeUrl(u) {
  try {
    const parsed = new URL(u, window.location.origin);
    return ['http:', 'https:'].includes(parsed.protocol) ? parsed.href : '';
  } catch { return ''; }
}
img.setAttribute('src', safeUrl(v.image));
```

Never build an event-handler attribute from data. `onclick="doThing('${v.id}')"` is a
string that becomes code; a value containing a quote escapes into it. Attach the handler
instead:

```js
btn.addEventListener('click', () => doThing(v.id));   // v.id is never parsed
```

## 4. If you must produce HTML, escape at the boundary

Only when the output genuinely has to be an HTML string. Escape every interpolated value,
with a function that handles all five characters:

```js
const escapeHtml = (s) => String(s)
  .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;').replaceAll("'", '&#39;');

el.innerHTML = `<div class="title">${escapeHtml(v.make)}</div>`;
```

`&` must be replaced **first**, or you double-escape the entities you just inserted.

## The four ways this goes wrong

- **Escaping in the helper, then concatenating after.** `escapeHtml(v.name) + '</div>' + v.note`
  — the second value never went through it. Escape at every interpolation, or use §1–§2 and
  have no interpolations to miss.
- **Blocklisting payloads.** Stripping `<script>` or `onerror` is not a defence; there are
  more vectors than any list. Nothing in this document blocklists anything.
- **Escaping the wrong context.** HTML escaping does not make a value safe inside a `<script>`
  block, a `style` attribute, or a URL. If the value lands in one of those, that context needs
  its own encoding — and usually the answer is not to put it there.
- **Fixing the renderer and leaving the helper.** The markup is often assembled in a function
  that *returns* a string and assigned somewhere else entirely. Fixing the assignment does
  nothing if the helper still concatenates. Follow the value to where the string is built.

## What not to do

Do not delete the renderer, the field, or the feature. An empty page has no XSS and no
product, and the harness measures the working endpoints and the route surface precisely so
that removing the thing being measured is not a way through. The vehicle cards must still
render vehicle data when you are done.
