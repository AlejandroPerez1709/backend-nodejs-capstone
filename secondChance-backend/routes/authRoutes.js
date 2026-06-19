const express = require('express')
const bcryptjs = require('bcryptjs')
const jwt = require('jsonwebtoken')
const connectToDatabase = require('../models/db')
const router = express.Router()
const dotenv = require('dotenv')
const pino = require('pino')
const { body, validationResult } = require('express-validator')

const logger = pino()
dotenv.config()
const JWT_SECRET = process.env.JWT_SECRET

router.post('/register', async (req, res) => {
  try {
    const db = await connectToDatabase()
    const collection = db.collection('users')

    const existingEmail = await collection.findOne({ email: req.body.email })
    if (existingEmail) {
      logger.error('Email id already exists')
      return res.status(400).json({ error: 'Email id already exists' })
    }

    const salt = await bcryptjs.genSalt(10)
    const hash = await bcryptjs.hash(req.body.password, salt)

    const newUser = await collection.insertOne({
      email: req.body.email,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      password: hash,
      createdAt: new Date()
    })

    const payload = { user: { id: newUser.insertedId } }
    const authtoken = jwt.sign(payload, JWT_SECRET)

    logger.info('User registered successfully')
    res.status(201).json({ authtoken, email: req.body.email })
  } catch (e) {
    logger.error(e)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

router.post('/login', async (req, res) => {
  try {
    const db = await connectToDatabase()
    const collection = db.collection('users')
    const theUser = await collection.findOne({ email: req.body.email })

    if (!theUser) {
      logger.error('User not found')
      return res.status(404).json({ error: 'User not found' })
    }

    const isMatch = await bcryptjs.compare(req.body.password, theUser.password)
    if (!isMatch) {
      logger.error('Passwords do not match')
      return res.status(401).json({ error: 'Wrong password' })
    }

    const payload = { user: { id: theUser._id.toString() } }
    const authtoken = jwt.sign(payload, JWT_SECRET)

    logger.info('User logged in successfully')
    return res.status(200).json({ authtoken, userName: theUser.firstName, userEmail: theUser.email })
  } catch (e) {
    logger.error(e)
    return res.status(500).json({ error: 'Internal server error', details: e.message })
  }
})

router.put('/update', [
  body('name').isLength({ min: 1 }).withMessage('Name is required')
], async (req, res) => {
  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() })
  }

  try {
    const email = req.headers.email
    if (!email) {
      return res.status(400).json({ error: 'Email not found in headers' })
    }

    const db = await connectToDatabase()
    const collection = db.collection('users')
    const existingUser = await collection.findOne({ email })

    if (!existingUser) {
      return res.status(404).json({ error: 'User not found' })
    }

    const updatedUser = await collection.findOneAndUpdate(
      { email },
      { $set: { firstName: req.body.name, updatedAt: new Date() } },
      { returnDocument: 'after' }
    )

    const payload = { user: { id: updatedUser.value._id.toString() } }
    const authtoken = jwt.sign(payload, JWT_SECRET)

    logger.info('User updated successfully')
    res.json({ authtoken })
  } catch (error) {
    logger.error(error)
    return res.status(500).json({ error: 'Internal Server Error' })
  }
})

module.exports = router
