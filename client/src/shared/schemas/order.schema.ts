import { z } from "zod"

export const orderSchema = z.object({
    clientId: z.number().min(1, "Выберите клиента"),
    city: z.string().min(2, "Введите город"),
    propertyType: z.enum(["HOUSE", "APARTMENT", "COMMERCIAL"]),
    dealType: z.enum(["SELL", "RENT"]),
    description: z.string().min(5, "Добавьте описание")
})

export type OrderFormData = z.infer<typeof orderSchema>