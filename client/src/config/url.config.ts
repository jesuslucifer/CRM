export const APP_URL = import.meta.env.VITE_APP_URL as string

export const PUBLIC_URL = {
	root: (url = '') => `${url ? url : ''}`,

	home: () => PUBLIC_URL.root('/'),
	login: () => PUBLIC_URL.root('/login'),
	register: () => PUBLIC_URL.root('/register'),
	forgot: () => PUBLIC_URL.root('/forgot-password'),

	product: (id = '') => PUBLIC_URL.root(`/product/${id}`),
	category: (id = '') => PUBLIC_URL.root(`/category/${id}`)
}

export const DASHBOARD_URL = {
	root: (url = '') => `/dashboard${url ? url : ''}`,

	home: () => DASHBOARD_URL.root('/'),
}

