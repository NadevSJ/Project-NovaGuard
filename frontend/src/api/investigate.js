import client from './client'

export async function investigate(input, inputTypeHint = 'auto') {
  const { data } = await client.post('/investigate', { input, input_type_hint: inputTypeHint })
  return data
}

export async function investigateEmail({ sender, subject, body }) {
  const { data } = await client.post('/investigate/email', { sender, subject, body })
  return data
}

export async function investigateScreenshot(file) {
  const form = new FormData()
  form.append('file', file)
  const { data } = await client.post('/investigate/screenshot', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data
}
