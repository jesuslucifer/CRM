import Cookies from 'js-cookie'

export const EnumTokens = {
	ACCESS_TOKEN: 'accessToken',
	REFRESH_TOKEN: 'refreshToken'
} as const;

export const getAccessToken = () => {
	const accessToken = Cookies.get(EnumTokens.ACCESS_TOKEN)
	return accessToken || null
}
export const getRefreshToken = () => {
	const refreshToken = Cookies.get(EnumTokens.REFRESH_TOKEN)
	return refreshToken || null
}
export const saveTokensStorage = (accessToken: string, refreshToken: string) => {
	Cookies.set(EnumTokens.ACCESS_TOKEN, accessToken, {
		domain: import.meta.env.VITE_APP_DOMAIN,
		sameSite: 'strict',
		expires: 1
	})
	Cookies.set(EnumTokens.REFRESH_TOKEN, refreshToken, {
		domain: import.meta.env.VITE_APP_DOMAIN,
		sameSite: 'strict',
		expires: 1
	})
}

export const removeFromStorage = () => {
  Cookies.remove(EnumTokens.ACCESS_TOKEN, {
    domain: import.meta.env.VITE_APP_DOMAIN,
  })

  Cookies.remove(EnumTokens.REFRESH_TOKEN, {
    domain: import.meta.env.VITE_APP_DOMAIN,
  })

}
