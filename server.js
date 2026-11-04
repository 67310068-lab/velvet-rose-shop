require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

// ให้เซิร์ฟเวอร์เปิดอ่านไฟล์หน้าเว็บ (HTML, CSS, JS) ในโฟลเดอร์หลัก
app.use(express.static(__dirname));

let memoryUsers = [];
let memoryOrders = [
  {
    id: 'ORD-9021',
    customerName: 'Customer Test (Member)',
    email: 'jomsurang2548.to@gmail.com',
    items: 'Miracle Rose Serum (1), Rose Glow Blush On (1)',
    total: 1670,
    status: 'ชำระเงินเรียบร้อย',
    date: '05/11/2026 14:15'
  },
  {
    id: 'ORD-9022',
    customerName: 'คุณมณี รุ่งเรือง',
    email: 'manee@gmail.com',
    items: 'Velvet Matte Lipstick (2), Silk Foundation SPF30 (1)',
    total: 1590,
    status: 'รอชำระเงิน',
    date: '05/11/2026 15:30'
  }
];
let isDbConnected = false;

mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 2000 })
  .then(() => {
    isDbConnected = true;
    console.log('✅ Connected to MongoDB Atlas!');
  })
  .catch(() => {
    console.log('⚠️ สลับใช้ระบบประมวลผลสำรอง');
  });

const userSchema = new mongoose.Schema({ name: String, email: String, password: String, isVerified: Boolean, otp: String, otpExpires: Date });
const User = mongoose.model('User', userSchema);

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// กำหนดให้เมื่อกดเข้าลิงก์หลัก ให้เปิดหน้า index.html ทันที
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// 1. API สมัครสมาชิก (ส่ง OTP)
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

    if (isDbConnected) {
      let user = await User.findOne({ email });
      if (user && user.isVerified) return res.status(400).json({ message: 'อีเมลนี้ถูกใช้งานแล้ว' });
      if (!user) user = new User({ name, email, password: hashedPassword, otp, otpExpires });
      else { user.name = name; user.password = hashedPassword; user.otp = otp; user.otpExpires = otpExpires; }
      await user.save();
    } else {
      let user = memoryUsers.find(u => u.email === email);
      if (user && user.isVerified) return res.status(400).json({ message: 'อีเมลนี้ถูกใช้งานแล้ว' });
      if (!user) {
        user = { name, email, password: hashedPassword, otp, otpExpires, isVerified: false };
        memoryUsers.push(user);
      } else {
        user.name = name; user.password = hashedPassword; user.otp = otp; user.otpExpires = otpExpires;
      }
    }

    try {
      await transporter.sendMail({
        from: `"Velvet Rose Beauty" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: '🔑 รหัส OTP ยืนยันการสมัครสมาชิก Velvet Rose Beauty',
        html: `
          <div style="font-family: Arial, sans-serif; padding: 24px; border: 2px solid #8C2435; border-radius: 16px; background-color: #FDFBF7;">
            <h2 style="color: #681322;">ยินดีต้อนรับสู่ Velvet Rose Beauty</h2>
            <p style="color: #581C25;">รหัสยืนยันตัวตน (OTP) สำหรับสมัครสมาชิกของคุณคือ:</p>
            <h1 style="color: #8C2435; font-size: 38px; letter-spacing: 6px; margin: 16px 0;">${otp}</h1>
            <p style="color: #8C7074; font-size: 13px;">รหัสนี้จะหมดอายุภายใน 10 นาที</p>
          </div>
        `
      });
      res.json({ message: 'ส่งรหัส OTP เรียบร้อยแล้ว' });
    } catch (mailErr) {
      console.log('⚠️ Gmail Fallback OTP:', otp);
      res.json({ message: `ส่ง OTP เรียบร้อย! (รหัส OTP คือ: ${otp})` });
    }
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// 2. API ยืนยัน OTP
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    let user = isDbConnected ? await User.findOne({ email }) : memoryUsers.find(u => u.email === email);

    if (!user || user.otp !== otp) return res.status(400).json({ message: 'รหัส OTP ไม่ถูกต้องหรือหมดอายุ' });

    user.isVerified = true;
    user.otp = null;
    if (isDbConnected) await user.save();

    const token = jwt.sign({ id: user.email }, process.env.JWT_SECRET || 'secret');
    res.json({ message: 'ยืนยันตัวตนสำเร็จ สมัครสมาชิกเรียบร้อย!', token, name: user.name });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// 3. API เข้าสู่ระบบลูกค้า
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    let user = isDbConnected ? await User.findOne({ email }) : memoryUsers.find(u => u.email === email);

    if (!user) {
      const displayName = email.split('@')[0] || 'Member';
      const hashedPassword = await bcrypt.hash(password || '123456', 10);
      user = { name: displayName, email, password: hashedPassword, isVerified: true };
      
      if (!isDbConnected) {
        memoryUsers.push(user);
      } else {
        const newUser = new User({ name: displayName, email, password: hashedPassword, isVerified: true });
        await newUser.save();
        user = newUser;
      }
    }

    const token = jwt.sign({ id: user.email }, process.env.JWT_SECRET || 'secret');
    res.json({ message: 'เข้าสู่ระบบสำเร็จ!', token, name: user.name || 'Member', email: user.email });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// 4. API สินค้า 12 รายการ
app.get('/api/products', (req, res) => {
  const defaultProducts = [
    { id: 1, name: 'Velvet Matte Lipstick', price: 350, description: 'ลิปสติกเนื้อแมตต์กำมะหยี่ ติดทนนาน 16 ชั่วโมง', image: 'https://images.unsplash.com/photo-1586495777744-4413f21062fa?q=80&w=800' },
    { id: 2, name: 'Rose Glow Blush On', price: 420, description: 'บลัชออนสีชมพูกุหลาบประกายชิมเมอร์ละเอียด', image: 'https://images.unsplash.com/photo-1596462502278-27bfdc403348?q=80&w=800' },
    { id: 3, name: 'Silk Foundation SPF30', price: 890, description: 'รองพื้นเนื้อบางเบาสัมผัส Silk ผิวฉ่ำโกลว์ คุมมัน', image: 'https://images.unsplash.com/photo-1631729371254-42c2892f0e6e?q=80&w=800' },
    { id: 4, name: 'Miracle Rose Serum', price: 1250, description: 'เซรั่มเข้มข้นสกัดจากสเต็มเซลล์กุหลาบฝรั่งเศส', image: 'https://images.unsplash.com/photo-1620916566398-39f1143ab7be?q=80&w=800' },
    { id: 5, name: 'French Rose Perfume 50ml', price: 1850, description: 'น้ำหอมกลิ่นกุหลาบฝรั่งเศส หรูหรา เย้ายวน', image: 'https://images.unsplash.com/photo-1592945403244-b3fbafd7f539?q=80&w=800' },
    { id: 6, name: 'Rose Cleansing Balm', price: 690, description: 'คลีนซิ่งบาล์มทำความสะอาดผิวหน้าล้ำลึก', image: 'https://images.unsplash.com/photo-1556228720-195a672e8a03?q=80&w=800' },
    { id: 7, name: 'Rose Quartz Lip Gloss', price: 390, description: 'ลิปกลอสเพิ่มความอวบอิ่ม ประกายมุกระยิบระยับ', image: 'https://images.unsplash.com/photo-1617897903246-719242758050?q=80&w=800' },
    { id: 8, name: 'Diamond Highlighting Powder', price: 550, description: 'ไฮไลท์เนื้อฝุ่นประกายเพชร สว่างกระจ่างใส', image: 'https://images.unsplash.com/photo-1522337360788-8b13dee7a37e?q=80&w=800' },
    { id: 9, name: 'Rose Water Hydrating Mist', price: 490, description: 'สเปรย์น้ำแร่ฉีดหน้าละอองละเอียด คืนความสดชื่น', image: 'https://images.unsplash.com/photo-1608248543803-ba4f8c70ae0b?q=80&w=800' },
    { id: 10, name: 'Velvet Rose Body Lotion', price: 780, description: 'โลชั่นบำรุงผิวกายกลิ่นกุหลาบ ให้ผิวเนียนนุ่ม', image: 'https://images.unsplash.com/photo-1570172619644-dfd03ed5d881?q=80&w=800' },
    { id: 11, name: 'Luxury Rose Eyeshadow Palette', price: 1190, description: 'พาเลตต์อายแชโดว์ 12 เฉดสี พิกเมนต์แน่น', image: 'https://images.unsplash.com/photo-1583241799080-91739c1757c5?q=80&w=800' },
    { id: 12, name: 'Rosehip Nourishing Oil', price: 950, description: 'ออยล์บำรุงผิวหน้าเข้มข้น ลดเลือนริ้วรอย', image: 'https://images.unsplash.com/photo-1616683693504-3ea7e9ad6fec?q=80&w=800' }
  ];
  res.json(defaultProducts);
});

// 5. API สั่งซื้อของลูกค้า
app.post('/api/orders/checkout', (req, res) => {
  const { customerName, email, items, total } = req.body;
  const now = new Date();
  const formattedDate = `${now.getDate().toString().padStart(2, '0')}/${(now.getMonth()+1).toString().padStart(2, '0')}/${now.getFullYear()} ${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`;
  const orderId = 'ORD-' + Math.floor(1000 + Math.random() * 9000);

  const newOrder = {
    id: orderId,
    customerName: customerName || 'Customer Test (Member)',
    email: email || 'jomsurang2548.to@gmail.com',
    items: items.map(i => `${i.name} (${i.qty})`).join(', '),
    total: total,
    status: 'รอชำระเงิน',
    date: formattedDate
  };

  memoryOrders.unshift(newOrder);
  res.json({ message: `สั่งซื้อสำเร็จ! เลขที่ใบสั่งซื้อ: ${orderId}`, orderId });
});

// 6. API ล็อกอินแอดมิน (รหัสผ่าน: 1234)
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === '1234') {
    res.json({ success: true, message: 'เข้าสู่ระบบแอดมินสำเร็จ' });
  } else {
    res.status(401).json({ success: false, message: 'รหัสผ่านแอดมินไม่ถูกต้อง' });
  }
});

// 7. API Admin Orders
app.get('/api/admin/orders', (req, res) => res.json(memoryOrders));

app.post('/api/admin/orders/confirm', (req, res) => {
  const { orderId } = req.body;
  const order = memoryOrders.find(o => o.id === orderId);
  if (order) {
    order.status = order.status === 'ชำระเงินเรียบร้อย' ? 'รอชำระเงิน' : 'ชำระเงินเรียบร้อย';
    return res.json({ message: 'อัปเดตสถานะการชำระเงินเรียบร้อย!', order });
  }
  res.status(404).json({ message: 'ไม่พบคำสั่งซื้อ' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));