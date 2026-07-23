FROM node:20-alpine

WORKDIR /app

COPY --chown=node:node package.json package-lock.json ./
RUN npm ci

COPY --chown=node:node . .

USER node

EXPOSE 5173

CMD ["npm", "run", "preview", "--", "--host", "0.0.0.0", "--port", "5173"]
