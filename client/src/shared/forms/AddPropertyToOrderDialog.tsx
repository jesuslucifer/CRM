import { useForm } from "react-hook-form"

import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
    DialogFooter
} from "@/components/ui/dialog"

import {
    Form,
    FormField,
    FormItem,
    FormLabel,
    FormControl
} from "@/components/ui/form"

import { Button } from "@/components/ui/button"

import { useCurrentCompany } from "../hooks/useCompany"
import { useAddPropertyToOrder } from "../hooks/useOrder"
import type { IOrder } from "@/types/order.interface"
import { useGetCompanyProperty } from "../hooks/useProperty"
import { Checkbox } from "@/components/ui/checkbox"

interface Props {
    order: IOrder
}

interface FormValues {
    propertyIds: number[]
}

export default function AddPropertyToOrderDialog({ order }: Props) {

    const form = useForm<FormValues>({
        defaultValues: {
            propertyIds: []
        }
    })

    const { data: company } = useCurrentCompany()
    const { data: properties } = useGetCompanyProperty(company?.id!)
    const { mutate: addProperties, isPending } = useAddPropertyToOrder(company?.id!)
    const orderId = order.id;

    const onSubmit = (data: FormValues) => {
        const propertyIds = data.propertyIds
        addProperties({ orderId, propertyIds })
    }

    return (
        <Dialog>

            <DialogTrigger asChild>
                <Button variant="outline">
                    Добавить недвижимость
                </Button>
            </DialogTrigger>

            <DialogContent className="max-w-2xl">

                <DialogHeader>
                    <DialogTitle>
                        Добавление недвижимости в заявку
                    </DialogTitle>
                </DialogHeader>

                <Form {...form}>
                    <form
                        onSubmit={form.handleSubmit(onSubmit)}
                        className="space-y-6"
                    >

                        <div className="space-y-4">

                            <h3 className="text-sm font-semibold text-muted-foreground">
                                Доступные объекты
                            </h3>

                            <div className="max-h-[300px] overflow-y-auto space-y-3 pr-2">

                                {
                                    properties?.length ? (
                                        properties?.map((property) => (
                                            <FormField
                                                key={property.id}
                                                control={form.control}
                                                name="propertyIds"
                                                render={({ field }) => {

                                                    const isChecked = field.value?.includes(property.id)

                                                    return (
                                                        <FormItem className="flex items-center justify-between border rounded-xl p-3 hover:bg-slate-50 transition">

                                                            <div>
                                                                <p className="font-medium">
                                                                    {property.title}
                                                                </p>
                                                                <p className="text-xs text-muted-foreground">
                                                                    {property.city}, {property.address}
                                                                </p>
                                                            </div>

                                                            <FormControl>
                                                                <Checkbox
                                                                    checked={isChecked}
                                                                    onCheckedChange={(checked) => {
                                                                        if (checked) {
                                                                            field.onChange([
                                                                                ...field.value,
                                                                                property.id
                                                                            ])
                                                                        } else {
                                                                            field.onChange(
                                                                                field.value.filter(id => id !== property.id)
                                                                            )
                                                                        }
                                                                    }}
                                                                />
                                                            </FormControl>

                                                        </FormItem>
                                                    )
                                                }}
                                            />
                                        ))) : (
                                        <p className="text-sm text-muted-foreground">
                                            Нет доступных объектов
                                        </p>
                                    )}

                            </div>

                        </div>

                        <DialogFooter>

                            <Button
                                type="submit"
                                disabled={isPending}
                            >
                                {isPending ? "Добавление..." : "Добавить в заявку"}
                            </Button>

                        </DialogFooter>

                    </form>
                </Form>

            </DialogContent>

        </Dialog>
    )
}