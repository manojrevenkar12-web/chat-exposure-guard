resource "google_storage_bucket" "voice_notes" {
  name                        = "lumachat-voice-notes-eu"
  location                    = "EU"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}

resource "google_service_account" "media_api" {
  account_id   = "media-api"
  display_name = "media api"
}

resource "google_storage_bucket_iam_member" "voice_notes_reader" {
  bucket = google_storage_bucket.voice_notes.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.media_api.email}"
}

resource "google_storage_bucket_iam_binding" "voice_notes_admins" {
  bucket  = google_storage_bucket.voice_notes.name
  role    = "roles/storage.admin"
  members = ["group:platform-oncall@lumachat.example.com"]
}
