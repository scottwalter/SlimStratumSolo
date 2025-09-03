# Use a lightweight Node.js image (Alpine Linux variant)
FROM node:20-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json (if present)
# This step allows Docker to cache dependencies if they don't change
COPY package*.json ./

# Install production dependencies based on package.json
RUN npm install --omit=dev

# Copy the rest of the application code to the working directory
COPY . .

# Expose the port the proxy server will be listening on
EXPOSE 3333

# Command to run the application when the container starts
CMD ["npm", "start"]
