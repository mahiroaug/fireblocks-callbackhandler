FROM node:18

WORKDIR /app

COPY package*.json ./

RUN npm install

COPY . .
COPY callback_private.pem ./
COPY cosigner_public.pem ./

EXPOSE 3000

CMD ["node", "app.js"]
