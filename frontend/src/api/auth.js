import client from './client'

export async function register({ email, username, password }) {
  const { data } = await client.post('/auth/register', { email, username, password })
  return data
}

export async function login({ email, password }) {
  const { data } = await client.post('/auth/login', { email, password })
  return data
}

export async function getMe() {
  const { data } = await client.get('/auth/me')
  return data
}
