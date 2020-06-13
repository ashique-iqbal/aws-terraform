# Configure the AWS credentials
provider "aws" {
  region  = "ap-south-1"
  profile = "lw"  
}
# Create Key pair
resource "aws_key_pair" "key" {
  key_name   = "loginkey"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDUFw3hyptugfTh5yzVCwkuMRTzN8llNhYZukilPYLJFEDn7o41VHPCVPfiI084+uVFmXzKD/xPeHp85B2wRqEj+WMxkACMWLPOt0WJY6RSpAHfzxFmR4NEQTzPVLIExX4tYD+AEqhuMBkwyjJIZ8At/OxDAjdkZIfg+V3okRoCc9hlBqm7a4SjPU0hcCvUR6KOK/KttKICrvAsBTDf/DQdQq/Wyv7sUPz/mUOPblVPhPwgvt4kVHWLIdTOJJG+c0m/nKzRdPH/R7ywpibjmPlzWwX97fa/cu3NLSuDwiLOc8XObH94j1g/AQYu2k6Bg31l+0soh60mBzmbsjavSFdF imported-openssh-key"
}
# Creatind security groups
resource "aws_security_group" "firewall" {
  name        = "firewall"
  description = "Allow SSH AND HTTP"


  ingress {
    description = "Allow SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [ "0.0.0.0/0" ]
  }

  ingress {
    description = "Allow HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [ "0.0.0.0/0" ]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "firewall"
  }
}

# Creating variable for key

variable "key_name" {
  type= string
  default = "loginkey"
}

# Create AWS EC2 instance

resource "aws_instance" "web" {
  ami           = "ami-0447a12f28fddb066"
  instance_type = "t2.micro"
  availability_zone = "ap-south-1a"
  key_name      = var.key_name
  security_groups = [ aws_security_group.firewall.name ]
    
    user_data = <<-EOF
                #! /bin/bash
                sudo yum install httpd -y
                sudo systemctl start httpd
                sudo systemctl enable httpd
                sudo yum install git -y
                mkfs.ext4 /dev/xvdf1
                mount /dev/xvdf1 /var/www/html
                
                git clone https://github.com/ashique-iqbal/aws-terraform
                cd aws-terraform
                cp index.html /var/www/html/.
 EOF

  tags = {
     Name = "webserver"
  }
}

# Create EBS Volume 

resource "aws_ebs_volume" "ebsvol" {
  availability_zone = aws_instance.web.availability_zone
  size              = 1

  tags = {
    Name = "vol"
  }
}

#Attach EBS Volume to Instance 

resource "aws_volume_attachment" "ebs_attach" {
  device_name = "/dev/sdf"
  volume_id = aws_ebs_volume.ebsvol.id
  instance_id = aws_instance.web.id
}

# Creating S3 Bucket

resource "aws_s3_bucket" "webimages1" {
    bucket = "webimages1"
    acl    = "public-read"
    versioning {
	  enabled =true
    }
    tags = {
	  Name    = "webimages1"
	}    
}

# Creating Cloudfront

resource "aws_cloudfront_distribution" "webcf" {
    origin {
        domain_name = "webimages1.s3.amazonaws.com"
        origin_id = "S3-webimages1" 


        custom_origin_config {
            http_port = 80
            https_port = 80
            origin_protocol_policy = "match-viewer"
            origin_ssl_protocols = ["TLSv1", "TLSv1.1", "TLSv1.2"] 
        }
    }
       
    enabled = true


    default_cache_behavior {
        allowed_methods = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
        cached_methods = ["GET", "HEAD"]
        target_origin_id = "webimages"


        # Forward all query strings, cookies and headers
        forwarded_values {
            query_string = false
        
            cookies {
               forward = "none"
            }
        }
        viewer_protocol_policy = "allow-all"
        min_ttl = 0
        default_ttl = 3600
        max_ttl = 86400
    }
    # Restricts who is able to access this content
    restrictions {
        geo_restriction {
            # type of restriction, blacklist, whitelist or none
            restriction_type = "none"
        }
    }


    # SSL certificate for the service.
    viewer_certificate {
        cloudfront_default_certificate = true
    }
}