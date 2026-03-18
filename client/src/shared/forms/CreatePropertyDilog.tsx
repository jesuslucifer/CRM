import { Button } from "@/components/ui/button"
import {
    Dialog,
    DialogHeader,
    DialogTrigger,
    DialogContent,
    DialogTitle,
    DialogFooter,
} from "@/components/ui/dialog"

import {
    Form,
    FormControl,
    FormField,
    FormItem,
    FormLabel,
    FormMessage,
} from "@/components/ui/form"

import { Input } from "@/components/ui/input"
import { DialogClose } from "@radix-ui/react-dialog"

import { useForm } from "react-hook-form"
import { useCreateProperty } from "../hooks/useProperty"
import type { ICreateProperty } from "@/types/property.interface"
import { useCurrentCompany } from "../hooks/useCompany"

export default function CreatePropertyDialog() {

    const form = useForm<ICreateProperty>({
        mode: "onChange",
        defaultValues: {
            cadastralNumber: 0,
            title: "",
            description: "",
            propertyType: "HOUSE",
            dealType: "SELL",
            address: "",
            city: "",
            district: "",
            price: 0,
            salePrice: 0,
            area: 0,
            rooms: 0,
            floor: 0,
            totalFloors: 0,
            yearBuilt: 0,
            propertyStatus: "AVAILABLE"
        }
    })
    const company = useCurrentCompany()
    const { mutate: createProperty } = useCreateProperty(company.data?.id!)

    const onSubmit = (data: ICreateProperty) => {
        console.log(data)
        createProperty(data)
    }

    return (
        <Dialog>
            <Form {...form}>
                <form className="w-full">
                    <DialogTrigger className="px-3 py-1 border rounded-2xl">
                        Добавить объект
                    </DialogTrigger>

                    <DialogContent className="max-w-[600px]">

                        <DialogHeader>
                            <DialogTitle>Добавить объект недвижимости</DialogTitle>
                        </DialogHeader>

                        <div className="grid grid-cols-2 gap-4">

                            {/* title */}
                            <FormField
                                control={form.control}
                                name="title"
                                render={({ field }) => (
                                    <FormItem>
                                        <FormLabel>Название</FormLabel>
                                        <FormControl>
                                            <Input placeholder="Дом у озера" {...field} />
                                        </FormControl>
                                        <FormMessage />
                                    </FormItem>
                                )}
                            />

                            {/* cadastralNumber */}
                            <FormField
                                control={form.control}
                                name="cadastralNumber"
                                render={({ field }) => (
                                    <FormItem>
                                        <FormLabel>Кадастровый номер</FormLabel>
                                        <FormControl>
                                            <Input
                                                type="number"
                                                {...field}
                                                onChange={(e) =>
                                                    field.onChange(Number(e.target.value))
                                                }
                                            />
                                        </FormControl>
                                        <FormMessage />
                                    </FormItem>
                                )}
                            />

                            {/* address */}
                            <FormField
                                control={form.control}
                                name="address"
                                render={({ field }) => (
                                    <FormItem>
                                        <FormLabel>Адрес</FormLabel>
                                        <FormControl>
                                            <Input placeholder="ул. Ленина 10" {...field} />
                                        </FormControl>
                                        <FormMessage />
                                    </FormItem>
                                )}
                            />

                            {/* city */}
                            <FormField
                                control={form.control}
                                name="city"
                                render={({ field }) => (
                                    <FormItem>
                                        <FormLabel>Город</FormLabel>
                                        <FormControl>
                                            <Input placeholder="Москва" {...field} />
                                        </FormControl>
                                        <FormMessage />
                                    </FormItem>
                                )}
                            />

                            {/* district */}
                            <FormField
                                control={form.control}
                                name="district"
                                render={({ field }) => (
                                    <FormItem>
                                        <FormLabel>Район</FormLabel>
                                        <FormControl>
                                            <Input placeholder="Центральный" {...field} />
                                        </FormControl>
                                        <FormMessage />
                                    </FormItem>
                                )}
                            />

                            {/* price */}
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
                                                onChange={(e) =>
                                                    field.onChange(Number(e.target.value))
                                                }
                                            />
                                        </FormControl>
                                        <FormMessage />
                                    </FormItem>
                                )}
                            />

                            {/* area */}
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
                                                onChange={(e) =>
                                                    field.onChange(Number(e.target.value))
                                                }
                                            />
                                        </FormControl>
                                        <FormMessage />
                                    </FormItem>
                                )}
                            />

                            {/* rooms */}
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
                                                onChange={(e) =>
                                                    field.onChange(Number(e.target.value))
                                                }
                                            />
                                        </FormControl>
                                        <FormMessage />
                                    </FormItem>
                                )}
                            />

                        </div>

                        {/* description */}
                        <div className="mt-4">
                            <FormField
                                control={form.control}
                                name="description"
                                render={({ field }) => (
                                    <FormItem>
                                        <FormLabel>Описание</FormLabel>
                                        <FormControl>
                                            <textarea placeholder="Описание объекта" {...field} />
                                        </FormControl>
                                        <FormMessage />
                                    </FormItem>
                                )}
                            />
                        </div>

                        <DialogFooter className="mt-6">

                            <DialogClose asChild>
                                <Button variant="outline">Отмена</Button>
                            </DialogClose>

                            <Button
                                type="submit"
                                onClick={form.handleSubmit(onSubmit)}
                            >
                                Создать
                            </Button>

                        </DialogFooter>

                    </DialogContent>
                </form>
            </Form>
        </Dialog>
    )
}