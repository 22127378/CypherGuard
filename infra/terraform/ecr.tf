resource "aws_ecr_repository" "demo_app" {
  name                 = "${local.name}/demo-app"
  image_tag_mutability = "IMMUTABLE" # scenario H: tags cannot be overwritten
  force_delete         = true        # lab is destroyed every session

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
