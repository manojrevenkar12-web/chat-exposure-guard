resource "google_storage_bucket" "chat_images" {
  name                        = "kindred-chat-images"
  location                    = "EU"
  uniform_bucket_level_access = true
}

resource "google_storage_bucket_iam_member" "chat_images_public" {
  bucket = google_storage_bucket.chat_images.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_storage_bucket" "voice_notes" {
  name                        = "kindred-voice-notes"
  location                    = "EU"
  uniform_bucket_level_access = true
}

resource "google_storage_bucket_iam_binding" "voice_notes_readers" {
  bucket = google_storage_bucket.voice_notes.name
  role   = "roles/storage.objectViewer"
  members = [
    "serviceAccount:${google_service_account.voice.email}",
    "allAuthenticatedUsers",
  ]
}
