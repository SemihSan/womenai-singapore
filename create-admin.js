/**
 * Admin kullanıcı oluşturma scripti
 * Kullanım: node create-admin.js
 */

require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const mongoUri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/women_ai_chat';

// Admin User Schema
const adminUserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  shopDomain: { type: String, required: true },
  sessionToken: { type: String, default: null },
  tokenExpiry: { type: Date, default: null },
});

adminUserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

const AdminUser = mongoose.model('AdminUser', adminUserSchema);

async function createAdmin() {
  try {
    await mongoose.connect(mongoUri);
    console.log('✅ MongoDB bağlantısı başarılı');

    // Admin bilgileri - BUNLARI DEĞİŞTİR!
    const adminData = {
      username: 'admin',
      password: 'WomenAI2026!', // Bu şifreyi değiştir!
      shopDomain: 'singapur.semihcankadioglu.com.tr'
    };

    // Mevcut admin var mı kontrol et
    const existingAdmin = await AdminUser.findOne({ username: adminData.username });
    
    if (existingAdmin) {
      console.log('⚠️  Admin zaten mevcut. Şifre güncelleniyor...');
      existingAdmin.password = adminData.password;
      await existingAdmin.save();
      console.log('✅ Admin şifresi güncellendi!');
    } else {
      const admin = new AdminUser(adminData);
      await admin.save();
      console.log('✅ Admin kullanıcı oluşturuldu!');
    }

    console.log('\n📋 Giriş Bilgileri:');
    console.log('   URL: https://womenai.semihcankadioglu.com.tr/admin');
    console.log('   Kullanıcı: ' + adminData.username);
    console.log('   Şifre: ' + adminData.password);
    console.log('\n⚠️  ÖNEMLİ: Bu şifreyi güvenli bir yerde saklayın!');

    await mongoose.disconnect();
    process.exit(0);
  } catch (err) {
    console.error('❌ Hata:', err);
    process.exit(1);
  }
}

createAdmin();
