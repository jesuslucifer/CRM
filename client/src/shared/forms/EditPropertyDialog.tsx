import { useEffect } from "react"
import { useForm } from "react-hook-form"

import { Button } from "@/components/ui/button"
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
    DialogFooter,
    DialogTrigger
} from "@/components/ui/dialog"

import {
    Form,
    FormControl,
    FormField,
    FormItem,
    FormLabel,
    FormMessage
} from "@/components/ui/form"

import { Input } from "@/components/ui/input"

// import { useUpdateProperty } from "@/shared/hooks/useProperty"
import type { ICreateProperty } from "@/types/property.interface"
import { Textarea } from "@/components/ui/textarea"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useUpdateProperty } from "../hooks/useProperty"

interface Props {
    property: ICreateProperty
    id: number
}

export default function EditPropertyDialog({ property, id }: Props) {

    const { mutate: updateProperty } = useUpdateProperty(id)

    const form = useForm<ICreateProperty>({
        mode: "onChange",
        defaultValues: property
    })

    useEffect(() => {
        form.reset(property)
    }, [property])

    const onSubmit = (data: ICreateProperty) => {
        updateProperty(data)
    }

    return (
        <Dialog>

            <DialogTrigger asChild>
                <Button variant="outline">Редактировать</Button>
            </DialogTrigger>

            <DialogContent className="max-w-xl">

                <DialogHeader>
                    <DialogTitle>Редактировать объект</DialogTitle>
                </DialogHeader>

                <Form {...form}>
                    <form
                        onSubmit={form.handleSubmit(onSubmit)}
                        className="space-y-4"
                    >

                        {/* TITLE */}
                        <FormField
                            control={form.control}
                            name="title"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Название</FormLabel>
                                    <FormControl>
                                        <Input {...field} />
                                    </FormControl>
                                    <FormMessage />
                                </FormItem>
                            )}
                        />

                        {/* DESCRIPTION */}
                        <FormField
                            control={form.control}
                            name="description"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Описание</FormLabel>
                                    <FormControl>
                                        <Textarea {...field} />
                                    </FormControl>
                                </FormItem>
                            )}
                        />

                        {/* ADDRESS */}
                        <FormField
                            control={form.control}
                            name="address"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Адрес</FormLabel>
                                    <FormControl>
                                        <Input {...field} />
                                    </FormControl>
                                </FormItem>
                            )}
                        />

                        {/* CITY */}
                        <FormField
                            control={form.control}
                            name="city"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Город</FormLabel>
                                    <FormControl>
                                        <Input {...field} />
                                    </FormControl>
                                </FormItem>
                            )}
                        />

                        {/* PRICE */}
                        <FormField
                            control={form.control}
                            name="price"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Цена</FormLabel>
                                    <FormControl>
                                        <Input
                                            type="number"
                                            {...field}
                                            onChange={(e) => field.onChange(Number(e.target.value))}
                                        />
                                    </FormControl>
                                </FormItem>
                            )}
                        />

                        {/* AREA */}
                        <FormField
                            control={form.control}
                            name="area"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Площадь</FormLabel>
                                    <FormControl>
                                        <Input
                                            type="number"
                                            {...field}
                                            onChange={(e) => field.onChange(Number(e.target.value))}
                                        />
                                    </FormControl>
                                </FormItem>
                            )}
                        />

                        {/* ROOMS */}
                        <FormField
                            control={form.control}
                            name="rooms"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Комнаты</FormLabel>
                                    <FormControl>
                                        <Input
                                            type="number"
                                            {...field}
                                            onChange={(e) => field.onChange(Number(e.target.value))}
                                        />
                                    </FormControl>
                                </FormItem>
                            )}
                        />

                        {/* PROPERTY TYPE */}
                        <FormField
                            control={form.control}
                            name="propertyType"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Тип недвижимости</FormLabel>

                                    <Select
                                        onValueChange={field.onChange}
                                        defaultValue={field.value}
                                    >
                                        <FormControl>
                                            <SelectTrigger>
                                                <SelectValue placeholder="Тип" />
                                            </SelectTrigger>
                                        </FormControl>

                                        <SelectContent>
                                            <SelectItem value="HOUSE">Дом</SelectItem>
                                            <SelectItem value="APARTMENT">Квартира</SelectItem>
                                            <SelectItem value="COMMERCIAL">Коммерция</SelectItem>
                                        </SelectContent>

                                    </Select>

                                </FormItem>
                            )}
                        />

                        {/* STATUS */}
                        <FormField
                            control={form.control}
                            name="propertyStatus"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Статус</FormLabel>

                                    <Select
                                        onValueChange={field.onChange}
                                        defaultValue={field.value}
                                    >

                                        <FormControl>
                                            <SelectTrigger>
                                                <SelectValue />
                                            </SelectTrigger>
                                        </FormControl>

                                        <SelectContent>
                                            <SelectItem value="AVAILABLE">Доступен</SelectItem>
                                            <SelectItem value="SOLD">Продан</SelectItem>
                                            <SelectItem value="RENTED">Сдан</SelectItem>
                                        </SelectContent>

                                    </Select>

                                </FormItem>
                            )}
                        />

                        <DialogFooter>

                            <Button type="submit">
                                Сохранить изменения
                            </Button>

                        </DialogFooter>

                    </form>
                </Form>

            </DialogContent>

        </Dialog>
    )
}