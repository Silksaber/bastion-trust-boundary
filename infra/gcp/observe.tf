# Customer project. The Connections page fills in the tenant-specific delegate, the
# required APIs and the read permissions for the services you selected, so download the
# personalised copy from the panel rather than applying this file as it stands.
#
# The three quoted BASTION_* placeholders below keep this file valid Terraform on its
# own — `terraform validate` here is a real check — and are replaced by literal lists
# when the configuration is rendered for an organization.
# BASTION_SELECTED_SERVICES
terraform {
  required_providers {
    google = { source = "hashicorp/google", version = ">= 6.0, < 8.0" }
  }
}

variable "project_id" {
  type        = string
  description = "Customer Google Cloud project ID, not its number."
}

provider "google" { project = var.project_id }

# Enabling an API needs billing on the project and `serviceusage.services.enable`.
# `disable_on_destroy = false` is deliberate: several of these are shared APIs your own
# workloads may depend on, and removing this configuration must never turn one off.
resource "google_project_service" "observe" {
  for_each           = toset(["BASTION_REQUIRED_APIS"])
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# If a service account, custom role or binding of these names already exists in the
# project, `terraform apply` will fail rather than adopt it. Import the existing
# objects, or rename these, before applying.
resource "google_service_account" "observe" {
  project      = var.project_id
  account_id   = "bastion-observe"
  display_name = "Bastion security observation"
  depends_on   = [google_project_service.observe]
}

resource "google_project_iam_custom_role" "observe" {
  project     = var.project_id
  role_id     = "bastionObserve"
  title       = "Bastion Observe"
  description = "Read security configuration only; no workload data or write permissions."
  permissions = ["BASTION_PERMISSIONS"]
  depends_on  = [google_project_service.observe]
}

# Additive members preserve all existing customer IAM bindings.
resource "google_project_iam_member" "observe" {
  project = var.project_id
  role    = google_project_iam_custom_role.observe.name
  member  = "serviceAccount:${google_service_account.observe.email}"
}

# The only grant Bastion receives: one delegate may mint a short-lived token as this
# one observe account. Removing this binding revokes future impersonation at Google.
resource "google_service_account_iam_member" "tenant_delegate" {
  service_account_id = google_service_account.observe.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:BASTION_DELEGATE_EMAIL"
}

output "service_account_email" { value = google_service_account.observe.email }
output "project_id" { value = var.project_id }
