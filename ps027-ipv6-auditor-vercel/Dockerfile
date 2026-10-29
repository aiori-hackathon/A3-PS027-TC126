FROM node:20-alpine
WORKDIR /app
COPY package.json server.js ./
COPY api ./api
COPY public ./public
ENV NODE_ENV=production PORT=3000
USER node
EXPOSE 3000
CMD ["node", "server.js"]
