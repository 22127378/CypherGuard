# ECR lives in bootstrap so images and signatures survive lab destroy and the
# build pipeline works even when the lab is down.

resource "aws_ecr_repository" "demo_app" {
  #checkov:skip=CKV_AWS_136:AES256 is sufficient for a public demo image; a CMK adds cost with no extra control here
  name                 = "${var.project}/demo-app"
  image_tag_mutability = "IMMUTABLE" # scenario H: tags cannot be overwritten

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_lifecycle_policy" "demo_app" {
  repository = aws_ecr_repository.demo_app.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep the last 10 images (images and .sig/.att artifacts)"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}

output "ecr_repository_url" {
  value = aws_ecr_repository.demo_app.repository_url
}
