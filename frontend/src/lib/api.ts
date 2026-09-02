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

// Starts (or resumes) analysis. Returns immediately with { status, stage } —
// the analysis itself runs as a background job on the backend.
export const analyzeUpload = async (uploadId: string) => {
  const res = await api.post(`/api/analyze/${uploadId}`)
  return res.data
}

// Polled while an analysis is running. Returns { status, stage, error }.
export const getAnalysisStatus = async (uploadId: string) => {
  const res = await api.get(`/api/analyze/${uploadId}/status`)
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

// Cross-upload patterns rolled up from every completed analysis this user owns.
export const getTrends = async () => {
  const res = await api.get('/api/trends')
  return res.data
}