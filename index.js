const express = require('express');
const dotenv = require('dotenv'); 
const bcrypt=require("bcrypt")
const jwt=require("jsonwebtoken");
dotenv.config(); 
 const {PrismaClient}=require("@prisma/client")

const prisma = new PrismaClient();



const app = express();


app.use(express.json()); 
app.post('/api/auth/signup',async(req,res)=>{
  const {name,email,password}=req.body;
  const emailExists=await  prisma.user.findUnique({where:{email:email}});
  if(!email||!password){
    res.status(400).json({
      "message":"Missing fields"
    })
  }
  if(emailExists){
    res.status(400).json({
      "message":"Email already in use"
    })
  }
  const hash=await bcrypt.hash(password,10);
  console.log(hash);
  const user = await prisma.user.create({
      data: {
        email,
        password: hash,
        name,
      },
    });

    res.status(201).json({ message: "User created", user });



})
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Missing fields" });
  }

  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    return res.status(400).json({ message: "User not found" });
  }

  const passwordCheck = await bcrypt.compare(password, user.password);

  if (!passwordCheck) {
    return res.status(400).json({ message: "Invalid password" });
  }

  const token = jwt.sign({ email }, process.env.JWT_REFRESH_SECRET, { expiresIn: "7d" });

  return res.status(200).json({
    userdata: {
      id: user.id,
      email: user.email,
      name: user.name,
    },
    accesstoken: token,
  });
});


const PORT = process.env.PORT || 3000;  
app.listen(PORT, () => {
  console.log(`Backend server is running at http://localhost:${PORT}`);
});

module.exports=  app;