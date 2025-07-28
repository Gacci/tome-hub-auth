-- Create database if not exists
CREATE DATABASE IF NOT EXISTS auth CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create a user with remote access
CREATE USER IF NOT EXISTS 'auth-service'@'%' IDENTIFIED BY 'oA0^26.r}1dS@w';
GRANT ALL PRIVILEGES ON auth.* TO 'auth-service'@'%';

-- Apply privilege changes
FLUSH PRIVILEGES;


INSERT IGNORE INTO `Colleges` VALUES
   (25223,'California State University - San Marcos','csusm.edu',NULL,NULL,NULL),
   (25224,'CSU San Marcos - Temecula','csusm.edu',NULL,NULL,NULL),
   (25225,'CSU San Marcos - Temecula Higher Education Center','csusm.edu',NULL,NULL,NULL);