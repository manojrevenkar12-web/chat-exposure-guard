<script lang="ts">
  import showdown from "showdown";
  import sanitizeHtml from "sanitize-html";

  export let text: string;

  const converter = new showdown.Converter({ simplifiedAutoLink: true, tables: true });

  const options = {
    allowedTags: sanitizeHtml.defaults.allowedTags.concat(["img"]),
    allowedAttributes: {
      ...sanitizeHtml.defaults.allowedAttributes,
      img: ["src", "alt", "title"],
    },
    allowedSchemes: ["http", "https"],
  };

  $: html = sanitizeHtml(converter.makeHtml(text), options);
</script>

<div class="markdown">{@html html}</div>
