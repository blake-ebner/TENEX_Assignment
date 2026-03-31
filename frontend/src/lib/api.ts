import axios from 'axios'

const API_URL = process.env.NEXT_PUBLIC_API_URL

const api = axios.create({
  baseURL: API_URL,
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

export const register = async (username: string, password: string) => {
  const res = await api.post('/auth/register', { username, password })
  return res.data
}

export const login = async (username: string, password: string) => {
  const res = await api.post('/auth/login', { username, password })
  return res.data
}

export const uploadFile = async (file: File) => {
  const formData = new FormData()
  formData.append('file', file)
  const res = await api.post('/api/upload', formData)
  return res.data
}

export const analyzeUpload = async (uploadId: string) => {
  const res = await api.post(`/api/analyze/${uploadId}`)
  return res.data
}

export const getResults = async (uploadId: string) => {
  const res = await api.get(`/api/results/${uploadId}`)
  return res.data
}

export const getUploads = async () => {
  const res = await api.get('/api/uploads')
  return res.data
}