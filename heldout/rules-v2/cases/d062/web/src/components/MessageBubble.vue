<template>
  <div :class="['bubble', message.role]">
    <span class="author">{{ message.role === 'assistant' ? characterName : 'You' }}</span>
    <div class="body" v-html="formatted"></div>
    <time :datetime="message.createdAt">{{ timeLabel }}</time>
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue";

interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  text: string;
  createdAt: string;
}

const props = defineProps<{ message: ChatMessage; characterName: string }>();

const formatted = computed(() => props.message.text.replace(/\n/g, "<br>"));
const timeLabel = computed(() =>
  new Date(props.message.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
);
</script>
