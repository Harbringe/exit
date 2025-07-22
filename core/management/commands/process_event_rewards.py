from django.core.management.base import BaseCommand
from django.utils import timezone
from core.models import Event, EventRSVP, Wallet, Transaction

class Command(BaseCommand):
    help = 'Process event rewards and no-shows for all events whose end time has passed.'

    def handle(self, *args, **options):
        now = timezone.now()
        events = Event.objects.filter(end_datetime__lt=now)
        for event in events:
            # Process no-shows
            confirmed_rsvps = EventRSVP.objects.filter(event=event, status='confirmed')
            for rsvp in confirmed_rsvps:
                rsvp.status = 'no show'
                rsvp.save()
                self.stdout.write(f"Set RSVP {rsvp.id} to no show for event {event.id}")
            # Process rewards
            attended_rsvps = EventRSVP.objects.filter(event=event, status='attended')
            for rsvp in attended_rsvps:
                try:
                    wallet = Wallet.objects.get(user=rsvp.user)
                    wallet.deposit(event.token_reward)
                    Transaction.objects.create(
                        wallet=wallet,
                        amount=event.token_reward,
                        transaction_type='deposit',
                        status='completed',
                        description=f'Reward for attending event {event.title}',
                    )
                    self.stdout.write(f"Credited reward to user {rsvp.user.id} for event {event.id}")
                except Wallet.DoesNotExist:
                    self.stdout.write(f"Wallet not found for user {rsvp.user.id}") 