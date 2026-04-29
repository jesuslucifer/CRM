import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"

import {
    Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger
} from "@/components/ui/dialog"

import {
    Form, FormField, FormItem, FormLabel, FormControl, FormMessage
} from "@/components/ui/form"

import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Button } from "@/components/ui/button"

import {
    Select, SelectTrigger, SelectValue, SelectContent, SelectItem
} from "@/components/ui/select"

import { useCurrentCompany } from "@/shared/hooks/useCompany"
import { useGetCompanyClient } from "@/shared/hooks/useClient"
import { orderSchema, type OrderFormData } from "../schemas/order.schema"
import { useCreateOrder } from "../hooks/useOrder"
import { useProfile } from "../hooks/useProfile"

export default function CreateOrderDialog() {

    const { data: company } = useCurrentCompany()
    const { data: clients } = useGetCompanyClient(company?.id!)
    const me = useProfile()
    const { mutate, isPending } = useCreateOrder(company?.id!)

    const form = useForm<OrderFormData>({
        resolver: zodResolver(orderSchema),
        mode: "onChange"
    })

    const onSubmit = (data: OrderFormData) => {
        mutate(data)
    }

    return (
        <Dialog>

            <DialogTrigger asChild>
                <Button>+ Заявка</Button>
            </DialogTrigger>

            <DialogContent className="max-w-lg">

                <DialogHeader>
                    <DialogTitle>Создать заявку</DialogTitle>
                </DialogHeader>

                <Form {...form}>
                    <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-5">


                        <FormField
                            control={form.control}
                            name="clientId"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Клиент</FormLabel>

                                    <Select
                                        onValueChange={(val) => field.onChange(Number(val))}
                                    >
                                        <FormControl>
                                            <SelectTrigger>
                                                <SelectValue placeholder="Выберите клиента" />
                                            </SelectTrigger>
                                        </FormControl>

                                        <SelectContent>
                                            {clients?.map(client => (
                                                <SelectItem
                                                    key={client.id}
                                                    value={String(client.id)}
                                                >
                                                    {client.firstName} {client.lastName}
                                                </SelectItem>
                                            ))}
                                        </SelectContent>

                                    </Select>

                                    <FormMessage />
                                </FormItem>
                            )}
                        />


                        <FormField
                            control={form.control}
                            name="city"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Город</FormLabel>
                                    <FormControl>
                                        <Input placeholder="Москва" {...field} />
                                    </FormControl>
                                </FormItem>
                            )}
                        />


                        <FormField
                            control={form.control}
                            name="propertyType"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Тип недвижимости</FormLabel>

                                    <Select onValueChange={field.onChange}>
                                        <FormControl>
                                            <SelectTrigger>
                                                <SelectValue placeholder="Тип" />
                                            </SelectTrigger>
                                        </FormControl>

                                        <SelectContent>
                                            <SelectItem value="HOUSE">Дом</SelectItem>
                                            <SelectItem value="APARTMENT">Квартира</SelectItem>
                                            <SelectItem value="COMMERCIAL">Коммерческая</SelectItem>
                                        </SelectContent>
                                    </Select>

                                </FormItem>
                            )}
                        />

                        <FormField
                            control={form.control}
                            name="dealType"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Тип сделки</FormLabel>

                                    <Select onValueChange={field.onChange}>
                                        <FormControl>
                                            <SelectTrigger>
                                                <SelectValue placeholder="Сделка" />
                                            </SelectTrigger>
                                        </FormControl>

                                        <SelectContent>
                                            <SelectItem value="SELL">Продажа</SelectItem>
                                            <SelectItem value="RENT">Аренда</SelectItem>
                                        </SelectContent>
                                    </Select>

                                </FormItem>
                            )}
                        />

                        <FormField
                            control={form.control}
                            name="description"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Описание</FormLabel>
                                    <FormControl>
                                        <Textarea
                                            placeholder="Что ищет клиент..."
                                            {...field}
                                        />
                                    </FormControl>
                                </FormItem>
                            )}
                        />

                        <Button type="submit" disabled={isPending}>
                            {isPending ? "Создание..." : "Создать"}
                        </Button>

                    </form>
                </Form>

            </DialogContent>
        </Dialog>
    )
}