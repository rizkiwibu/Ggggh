# Gunakan image node.js versi 16
FROM node:16

# Buat direktori /app pada container
WORKDIR /app

# Salin package.json dan package-lock.json ke direktori /app pada container
COPY package*.json ./

# Jalankan perintah untuk menginstall dependensi yang dibutuhkan
RUN npm install

# Salin seluruh file ke dalam direktori /app pada container.
COPY . .

# Tetapkan port yang akan digunakan pada container
EXPOSE 3000

# Jalankan perintah untuk memulai aplikasi
CMD ["npm", "start"]