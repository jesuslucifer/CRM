import { useId } from "react"
export interface IUpload {
    file: File,
    url: string,
    options?: { onProgress?: (progress: number) => void }
}
export interface IUploadFile {
    name: string,
    size: string,
    type: string
}
export const Upload = () => {
    const id = useId()
    return (
        <label htmlFor={id}>
            <input type="file" id={id} />
        </label>
    )
}