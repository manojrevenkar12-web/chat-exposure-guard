resource "google_storage_bucket" "chat_images" {
  name                        = "lumachat-chat-images-eu"
  location                    = "EU"
  uniform_bucket_level_access = true

  lifecycle_rule {
    condition {
      age = 365
    }
    action {
      type = "Delete"
    }
  }
}

resource "google_storage_bucket_iam_member" "chat_images_viewer" {
  bucket = google_storage_bucket.chat_images.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
