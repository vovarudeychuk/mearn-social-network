import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import User from '../models/User.js'

/* REGISTER USER */
export const register = async (req, res) => {
  const {
    firstName,
    lastName,
    email,
    password,
    picturePath,
    friends,
    location,
    occupation,
  } = req.body

  if(!email || !password) {
    return res.status(400).json({ msg: 'Please enter all required fields.' });
  }

  try {
    const existingUser = await User.findOne({ email })
    if(existingUser) {
      return res.status(400).json({ msg: 'An account with this email already exists.' });
    }

    const salt = await bcrypt.genSalt(Number(process.env.SALT_ROUNDS || 10))
    const passwordHash = await bcrypt.hash(password, salt)

    const newUser = new User({
      firstName,
      lastName,
      email,
      password: passwordHash,
      picturePath,
      friends,
      location,
      occupation,
      viewedProfile: Math.floor(Math.random() * 10000),
      impressions: Math.floor(Math.random() * 10000),
    })

    const savedUser = await newUser.save()
    res.status(201).json({
      user: {
        id: savedUser._id,
        firstName: savedUser.firstName,
        lastName: savedUser.lastName,
        email: savedUser.email,
        // send any more user fields you want to share
      }
    })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
}

/* LOGGING IN */
export const login = async (req, res) => {
  const { email, password } = req.body
  if(!email || !password) {
    return res.status(400).json({ msg: 'Please enter all required fields.' });
  }

  try {
    const user = await User.findOne({ email })
    if (!user) return res.status(400).json({ msg: 'No account with this email exists.' })

    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials.' })

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET)
    
    res.status(200).json({
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        // send any more user fields you want to share
      }
    })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
}
