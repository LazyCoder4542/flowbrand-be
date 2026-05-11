# Use the official Node.js image as the base image
FROM node:20-alpine

# Set the working directory inside the container
WORKDIR /app

COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application code to the working directory
COPY . .

RUN npm run build

# Change ownership of the app directory to the built-in 'node' user
RUN chown -R node:node /app

EXPOSE 5000

# Switch to the built-in non-root user
USER node

# Command to run the application
CMD ["npm", "run", "start:prod"]
