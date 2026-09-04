terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }

  # Backend remoto recomendado (descomentar y ajustar en el primer `terraform init`).
  # El bucket y la tabla DynamoDB se crean UNA vez fuera de este stack.
  # backend "s3" {
  #   bucket         = "interseguros-tfstate"
  #   key            = "firma-f2/prod/terraform.tfstate"
  #   region         = "sa-east-1"
  #   dynamodb_table = "interseguros-tfstate-lock"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
      Owner       = "Interseguros-Bolivia"
    }
  }
}
