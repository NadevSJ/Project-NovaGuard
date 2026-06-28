import client from './client'

export async function getHistory(page = 1, limit = 20) {
  const { data } = await client.get('/history', { params: { page, limit } })
  return data
}

export async function getHistoryItem(id) {
  const { data } = await client.get(`/history/${id}`)
  return data
}

export async function deleteHistoryItem(id) {
  await client.delete(`/history/${id}`)
}
