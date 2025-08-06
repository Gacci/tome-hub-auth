# Step 1: Build the app
FROM node:22 AS builder

ARG NODE_ENV=development

# Set working directory inside container
WORKDIR /app

# Copy only package files and install dependencies first (to optimize Docker layers)
COPY package*.json ./
RUN npm install

# Download the wait-for-it script
RUN curl -sS https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh -o wait-for-it.sh && \
    chmod +x wait-for-it.sh

# Copy the entire app (source code)
COPY . .

# Create the destination file based on the environment
#RUN if [ "$NODE_ENV" = "dev" ]; then \
#      cp .env.dev.dev .env.dev; \
#    elif [ "$NODE_ENV" = "staging" ]; then \
#      cp .env.staging .env.staging; \
#    fi

# Step 2: Build the app
RUN npm run build

# Step 3: Create the production image
FROM node:22

# Set working directory in container
WORKDIR /app

# Copy the build files from the builder stage
COPY --from=builder /app/dist /app/dist

# Copy wait-for-it.sh from the builder stage
COPY --from=builder /app/wait-for-it.sh /app/wait-for-it.sh

# Install only production dependencies (for smaller image size)
COPY package*.json ./
RUN npm install --only=production

# Install tzdata (for setting time zone)
RUN apt-get update && apt-get install -y tzdata

# Expose the port that the app will run on
EXPOSE 3000

# Run the app
CMD ["node", "dist/main.js"]
