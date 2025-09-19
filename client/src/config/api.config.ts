export const SERVER_URL = import.meta.env.VITE_SERVER_URL as string;

export const API_URL = {
  root: (url = "") => `${url ? url : ""}`,

  auth: (url = "") => API_URL.root(`/auth${url}`),
  users: (url = "") => API_URL.root(`/users${url}`),
  publications: (url = "") => API_URL.root(`/posts${url}`),
  files: (url = "") => API_URL.root(`/files${url}`),
  likes: (url = "") => API_URL.root(`/likes${url}`),
};
