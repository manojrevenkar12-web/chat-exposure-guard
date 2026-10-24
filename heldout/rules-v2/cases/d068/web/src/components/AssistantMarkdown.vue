<template>
  <div class="assistant-md" v-html="rendered"></div>
</template>

<script setup lang="ts">
import DOMPurify from "dompurify";
import { marked } from "marked";
import { computed } from "vue";

const props = defineProps<{ content: string }>();

marked.setOptions({ gfm: true, breaks: true });

const rendered = computed(() => DOMPurify.sanitize(marked.parse(props.content) as string));
</script>
