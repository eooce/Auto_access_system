FROM node:18-alpine

WORKDIR /app

COPY . .

RUN npm install

ENV PORT=7860
ENV NODE_ENV=production
# 管理密码
ENV ADMIN_PASSWORD=admin  

EXPOSE 7860

CMD ["node", "index.js"]