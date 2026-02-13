"""Event bus utilities for publishing and subscribing to events.

This module provides a lightweight in-process event bus that supports
subscriptions with automatic cleanup via weak references. Subscribers can
listen to specific event types, and events are dispatched to callbacks based
on the event type and its class hierarchy.

Examples:
    Basic usage:
    >>> class MyEvent:
    ...     def __init__(self, message: str) -> None:
    ...         self.message = message
    ...
    >>> bus = EventBus()
    >>> def handle(event: MyEvent) -> None:
    ...     print(event.message)
    ...
    >>> sub = bus.subscribe(MyEvent, handle)
    >>> bus.publish(MyEvent("hello"))
    hello
    >>> sub.unsubscribe()

    Using a context manager:
    >>> with bus.subscribe(MyEvent, handle):
    ...     bus.publish(MyEvent("context"))
    context
"""

from collections import defaultdict
import inspect
from types import TracebackType
from typing import (
    Any,
    Callable,
    DefaultDict,
    Generator,
    List,
    Tuple,
    Type,
    TypeVar,
    cast,
)
import weakref


E = TypeVar("E")
Callback = Callable[[E], None]


class Subscription:
    """Represents a subscription to a specific event type."""

    __slots__ = ("_bus_ref", "_event_type", "_callback_id", "_active")

    def __init__(
        self, bus: "EventBus", event_type: Type[Any], callback_id: int
    ) -> None:
        """Initialize a subscription for a callback registered on the bus.

        Args:
            bus: The owning event bus
            event_type: The event type this subscription targets
            callback_id: Internal callback identifier

        Examples:
            >>> class Event:
            ...     pass
            ...
            >>> bus = EventBus()
            >>> sub = Subscription(bus, Event, 1)
            >>> isinstance(sub, Subscription)
            True
        """
        self._bus_ref = weakref.ref(bus)
        self._event_type = event_type
        self._callback_id = callback_id
        self._active = True

    def unsubscribe(self) -> None:
        """Unregister the callback if it is still active.

        This is idempotent and safe to call multiple times.

        Examples:
            >>> class Event:
            ...     pass
            ...
            >>> bus = EventBus()
            >>> sub = bus.subscribe(Event, lambda evt: None)
            >>> sub.unsubscribe()
            >>> sub.unsubscribe()
        """
        if not self._active:
            return

        bus = self._bus_ref()
        if bus is None:
            self._active = False
            return

        bus.unsubscribe(self._event_type, self._callback_id)

        self._active = False

    def __enter__(self) -> "Subscription":
        """Return the subscription for use in a context manager.

        Returns:
            Subscription: The current subscription instance

        Examples:
            >>> class Event:
            ...     pass
            ...
            >>> bus = EventBus()
            >>> with bus.subscribe(Event, lambda evt: None) as sub:
            ...     isinstance(sub, Subscription)
            True
        """
        return self

    def __exit__(
        self, exc_type: Type[Any], exc_value: Any, traceback: TracebackType
    ) -> None:
        """Unsubscribe when exiting a context manager.

        Examples:
            >>> class Event:
            ...     pass
            ...
            >>> bus = EventBus()
            >>> with bus.subscribe(Event, lambda evt: None):
            ...     bus.publish(Event())
        """
        self.unsubscribe()


class EventBus:
    """In-process event bus for publishing and subscribing to events."""

    def __init__(self) -> None:
        """Initialize an empty event bus.

        Examples:
            >>> bus = EventBus()
            >>> isinstance(bus, EventBus)
            True
        """
        self._subs: DefaultDict[Type[Any], List[Tuple[int, Any]]] = defaultdict(list)
        self._next_id: int = 1

    def subscribe(self, event_type: Type[Any], callback: Callback[Any]) -> Subscription:
        """Subscribe a callback to a specific event type.

        Args:
            event_type: The event class to subscribe to
            callback: The callback invoked when an event is published

        Returns:
            Subscription: A subscription handle for later unsubscription

        Examples:
            >>> class Event:
            ...     def __init__(self, value: int) -> None:
            ...         self.value = value
            ...
            >>> bus = EventBus()
            >>> def handler(evt: Event) -> None:
            ...     print(evt.value)
            ...
            >>> sub = bus.subscribe(Event, handler)
            >>> bus.publish(Event(42))
            42
        """
        cb_ref: Any

        if inspect.ismethod(callback):
            cb_ref = weakref.WeakMethod(cast(Any, callback))
        else:
            cb_ref = callback

        callback_id = self._next_id
        self._next_id += 1

        self._subs[event_type].append((callback_id, cb_ref))
        return Subscription(self, event_type, callback_id)

    def publish(self, event: E) -> None:
        """Publish an event to all subscribers of its type hierarchy.

        The event is dispatched to callbacks registered for the event type
        and any of its base classes.

        Examples:
            >>> class Base:
            ...     pass
            ...
            >>> class Child(Base):
            ...     pass
            ...
            >>> bus = EventBus()
            >>> bus.subscribe(Base, lambda evt: print("base"))
            >>> bus.publish(Child())
            base
        """
        event_type = type(event)

        for etype in self._iter_event_types(event_type):
            self._dispatch_to(etype, event)

    def publish_as(self, event_type: Type[Any], event: E) -> None:
        """Publish an event as a specific event type.

        This bypasses the concrete event type and dispatches directly to
        subscribers of the provided event type.

        Args:
            event_type: The type to dispatch the event as
            event: The event instance to publish

        Examples:
            >>> class Base:
            ...     pass
            ...
            >>> class Child(Base):
            ...     pass
            ...
            >>> bus = EventBus()
            >>> bus.subscribe(Base, lambda evt: print("base"))
            >>> bus.publish_as(Base, Child())
            base
        """
        self._dispatch_to(event_type, event)

    def _dispatch_to(self, event_type: Type[Any], event: E) -> None:
        """Dispatch an event to callbacks registered for a given type.

        Dead weak references are skipped and cleaned up after dispatch.

        Examples:
            >>> class Event:
            ...     pass
            ...
            >>> bus = EventBus()
            >>> bus.subscribe(Event, lambda evt: print("hit"))
            >>> bus._dispatch_to(Event, Event())
            hit
        """
        if event_type not in self._subs:
            return

        alive: List[Tuple[int, Any]] = []

        for callback_id, cb_ref in self._subs[event_type]:
            cb = cb_ref() if isinstance(cb_ref, weakref.WeakMethod) else cb_ref

            if cb is None:
                continue

            try:
                cb(event)
            finally:
                alive.append((callback_id, cb_ref))

        self._subs[event_type] = alive

    def unsubscribe(self, event_type: Type[Any], callback_id: int) -> None:
        """Unsubscribe a callback from a specific event type.

        Args:
            event_type: The event type to unsubscribe from
            callback_id: The internal callback identifier

        Examples:
            >>> class Event:
            ...     pass
            ...
            >>> bus = EventBus()
            >>> sub = bus.subscribe(Event, lambda evt: None)
            >>> bus.unsubscribe(Event, sub._callback_id)
        """
        if event_type not in self._subs:
            return

        self._subs[event_type] = [
            (cid, ref) for cid, ref in self._subs[event_type] if cid != callback_id
        ]

        if not self._subs[event_type]:
            del self._subs[event_type]

    @staticmethod
    def _iter_event_types(concrete_type: Type[Any]) -> Generator[Type[Any], None, None]:
        """Iterate over event type hierarchy from most to least specific.

        Args:
            concrete_type: The concrete event class

        Yields:
            Type[Any]: Each class in the method resolution order until object

        Examples:
            >>> class Base:
            ...     pass
            ...
            >>> class Child(Base):
            ...     pass
            ...
            >>> list(EventBus._iter_event_types(Child))[:2]
            [<class '__main__.Child'>, <class '__main__.Base'>]
        """
        for t in concrete_type.mro():
            if t is object:
                break
            yield t


# Global event bus instance
EVENT_BUS = EventBus()
