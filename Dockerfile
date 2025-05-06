# Dockerfile for api-gateway

# Step 1: Base Image
FROM node:18-alpine As base

# Step 2: Working Directory
WORKDIR /app

# Step 3: Copy package files
COPY package*.json ./

# Step 4: Install production dependencies
# Dependencies like express-session, axios, http-proxy-middleware don't need special build tools
RUN npm ci --only=production

# Step 5: Copy application code
COPY . .

# Step 6: Expose the application port
# Your app uses process.env.GATEWAY_PORT || 3002
EXPOSE 3002

# Step 7: Run command
# Assumes your main file is gateway.js
CMD ["node", "app.js"]