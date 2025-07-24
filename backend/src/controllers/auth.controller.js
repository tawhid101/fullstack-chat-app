import bcrypt from 'bcryptjs'
import User from '../models/user.model.js'
import cloudinary from '../lib/cloudinary.js'
import { generateToken } from '../lib/utils.js'

export const signup = async (req, res) => {
	const { fullName, email, password } = req.body
	const errors = []

	try {
		// validity
		if (!fullName) errors.push('Name is required')
		if (!email) errors.push('Email is required')
		if (!password) {
			errors.push('Password is required')
		} else if (password.length < 6) {
			errors.push('password must be at least 6 characters')
		}

		if (errors.length > 0) {
			return res.status(400).json({ message: errors })
		}

		// check existing user
		const user = await User.findOne({ email })
		if (user) return res.status(400).json({ message: 'email already exists' })

		// hash password
		const hashedPW = await bcrypt.hash(password, 12)

		const newUser = new User({
			fullName,
			email,
			password: hashedPW,
		})

		if (newUser) {
			// generate jwt token and save to cookie
			generateToken(newUser._id, res)
			await newUser.save()

			res.status(201).json({
				_id: newUser._id,
				fullName: newUser.fullName,
				email: newUser.email,
				profilePic: newUser.profilePic,
			})
		} else {
			res.status(400).json({ message: 'invalid user data' })
		}
	} catch (error) {
		console.log('error in signup controller', error)
		res.status(500).json({ message: 'Internal server error' })
	}
}

export const login = async (req, res) => {
	const { email, password } = req.body

	try {
		const user = await User.findOne({ email })
		if (!user) {
			return res.status(404).json({ message: 'invalid credentials' })
		}

		const isCorrect = await bcrypt.compare(password, user.password)
		if (!isCorrect) {
			return res.status(404).json({ message: 'invalid credentials' })
		}

		generateToken(user._id, res)

		res.status(200).json({
			_id: user._id,
			fullName: user.fullName,
			email: user.email,
			profilePic: user.profilePic,
		})
	} catch (error) {
		console.log('error in login controller', error)
		res.status(500).json({ message: 'internal server error' })
	}
}

export const logout = async (req, res) => {
	try {
		res.cookie('jwt', '', { maxAge: 0 })
		res.status(200).json({ message: 'logged out successfully' })
	} catch (error) {
		console.log('error in login controller', error)
		res.status(500).json({ message: 'internal server error' })
	}
}

export const updateProfile = async (req, res) => {
	try {
		const { profilePic } = req.body
		const userId = req.user._id

		if (!profilePic) {
			return res.status(400).json({ message: 'Profile pic is required' })
		}

		const uploadResponse = await cloudinary.uploader.upload(profilePic)
		const updatedUser = await User.findByIdAndUpdate(
			userId,
			{
				profilePic: uploadResponse.secure_url,
			},
			{ new: true }
		)

		res.status(200).json(updatedUser)
	} catch (error) {
		console.log('error in update profile controller', error)
		res.status(500).json({ message: 'Internal server error' })
	}
}

export const checkAuth = (req, res) => {
	try {
		res.status(200).json(req.user)
	} catch (error) {
		console.log('error in checkAuth controller', error)
		res.status(500).json({ message: 'internal server error' })
	}
}
