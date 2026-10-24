<script lang="ts">
  import type { Message } from "$lib/types";

  export let message: Message;
  export let streaming = false;
</script>

<article class="reply" class:streaming>
  <header>{message.characterName}</header>
  <div class="content">
    {@html message.body}
  </div>
  {#if streaming}
    <span class="cursor" aria-hidden="true"></span>
  {/if}
</article>

<style>
  .reply { padding: 0.75rem 1rem; border-radius: 12px; background: var(--bubble-bg); }
  .cursor { display: inline-block; width: 0.5ch; height: 1em; background: currentColor; }
</style>
